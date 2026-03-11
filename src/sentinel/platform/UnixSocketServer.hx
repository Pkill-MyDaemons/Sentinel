package sentinel.platform;

using StringTools;

import sentinel.core.Logger;
import sentinel.platform.Verdict;
import sys.thread.Thread;
import sys.thread.Mutex;

/**
 * UnixSocketServer — multi-client Unix domain socket server.
 *
 * Design:
 *   - One accept-loop thread (blocks on accept())
 *   - Per-client handler thread (reads command, dispatches to analyzer, writes response)
 *   - Analysis callback is synchronous within the handler thread
 *     so the shell blocks until Sentinel responds
 *
 * Protocol (newline-delimited):
 *   Shell  → Sentinel : "<command>\n"
 *   Sentinel → Shell  : "ALLOW\n"
 *                      | "WARN:<reason>\n"
 *                      | "BLOCK\n"
 *
 * Timeout: if analysis takes > maxAnalysisMs, respond WARN and continue
 * analyzing asynchronously (avoids blocking the shell forever).
 */

class UnixSocketServer {

    var socketPath:String;
    var serverFd:Int = -1;
    var running:Bool = false;
    var acceptThread:Thread;
    var onCommand:String -> AnalysisResult;

    /** Max ms to wait for AI analysis before responding WARN and continuing */
    public var maxAnalysisMs:Int = 8000;

    public function new(socketPath:String, onCommand:String -> AnalysisResult) {
        this.socketPath = socketPath;
        this.onCommand = onCommand;
    }

    // ----------------------------------------------------------------
    // Lifecycle
    // ----------------------------------------------------------------

    public function start() {
        serverFd = UnixSocket.create(socketPath);
        if (serverFd < 0) {
            var err = UnixSocket.lastError();
            throw 'UnixSocketServer: failed to create socket at $socketPath (errno=$err)';
        }

        Logger.info('[Socket] Listening at $socketPath (fd=$serverFd)');
        running = true;
        acceptThread = Thread.create(acceptLoop);
    }

    public function stop() {
        running = false;
        if (serverFd >= 0) {
            UnixSocket.destroy(serverFd, socketPath);
            serverFd = -1;
        }
        Logger.info('[Socket] Server stopped');
    }

    // ----------------------------------------------------------------
    // Accept loop — runs in its own thread
    // ----------------------------------------------------------------

    function acceptLoop() {
        while (running) {
            var clientFd = UnixSocket.accept(serverFd);

            if (!running) break;

            if (clientFd < 0) {
                if (running) Logger.warn('[Socket] accept() failed — retrying...');
                Sys.sleep(0.1);
                continue;
            }

            // Set a generous per-client timeout so hanging clients don't
            // tie up the handler thread indefinitely
            UnixSocket.setTimeout(clientFd, maxAnalysisMs + 2000);

            // Handle each client in its own thread — allows concurrent analysis
            // (e.g., two terminal windows running commands simultaneously)
            var fd = clientFd; // capture for closure
            Thread.create(() -> handleClient(fd));
        }
    }

    // ----------------------------------------------------------------
    // Client handler — reads one command, analyzes, responds, closes
    // ----------------------------------------------------------------

    function handleClient(clientFd:Int) {
        var cmd:Null<String> = null;

        try {
            cmd = UnixSocket.read(clientFd);
        } catch (e:Dynamic) {
            Logger.warn('[Socket] Read error: $e');
            UnixSocket.closeClient(clientFd);
            return;
        }

        if (cmd == null || cmd.trim().length == 0) {
            UnixSocket.write(clientFd, "ALLOW");
            UnixSocket.closeClient(clientFd);
            return;
        }

        cmd = cmd.trim();
        Logger.debug('[Socket] Command received: $cmd');

        // Run analysis with a timeout guard
        var result = analyzeWithTimeout(cmd);

        // Encode response
        var response = switch result.verdict {
            case Allow:       "ALLOW";
            case Warn(r):     "WARN:" + sanitizeReason(r);
            case Block:       "BLOCK";
        };

        // Manual 'finally' logic
        var success = false;
        try {
            UnixSocket.write(clientFd, response);
            success = true;
        } catch (e:Dynamic) {
            Logger.warn('[Socket] Write error: $e');
        }
        // This runs regardless of success/fail, acting as a finally block
        UnixSocket.closeClient(clientFd);


        Logger.info('[Socket] → $response | cmd: ${cmd.substr(0, 60)}');
    }

    // ----------------------------------------------------------------
    // Analysis with timeout
    // ----------------------------------------------------------------

    /**
     * Runs onCommand() in a separate thread with a timeout.
     * If analysis takes too long, we respond WARN immediately and
     * let the analysis complete in the background (for logging).
     *
     * Uses a simple mutex + flag pattern since Haxe doesn't have
     * built-in futures/promises on all targets.
     */
    function analyzeWithTimeout(cmd:String):AnalysisResult {
        var mutex  = new Mutex();
        var done   = false;
        var result:AnalysisResult = { verdict: Allow, reason: "" };

        // Spawn analysis thread
        Thread.create(() -> {
            try {
                var r = onCommand(cmd);
                mutex.acquire();
                if (!done) {
                    result = r;
                    done = true;
                }
                mutex.release();
            } catch (e:Dynamic) {
                Logger.error('[Socket] Analysis threw: $e');
                mutex.acquire();
                if (!done) {
                    result = { verdict: Warn("analysis error — review manually"), reason: "" };
                    done = true;
                }
                mutex.release();
            }
        });

        // Poll for completion up to maxAnalysisMs
        var waited = 0;
        var pollMs = 50;
        while (waited < maxAnalysisMs) {
            Sys.sleep(pollMs / 1000.0);
            waited += pollMs;
            mutex.acquire();
            var isDone = done;
            mutex.release();
            if (isDone) return result;
        }

        // Timeout — mark done so background thread doesn't overwrite,
        // and return a WARN so the shell can proceed
        mutex.acquire();
        done = true;
        mutex.release();

        Logger.warn('[Socket] Analysis timeout for: $cmd');
        return {
            verdict: Warn("analysis timed out — proceeding with caution"),
            reason: ""
        };
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /**
     * Reason strings go back to the shell via nc and are displayed in the
     * terminal — strip newlines and limit length so they display cleanly.
     */
    static function sanitizeReason(r:String):String {
        var clean = r.split("\n").join(" | ").split("\r").join("");
        return clean.length > 200 ? clean.substr(0, 197) + "..." : clean;
    }
}
