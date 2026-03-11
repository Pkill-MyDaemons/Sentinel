package sentinel.platform;

using StringTools;

/**
 * Verdict — the decision returned by the socket server to the shell hook.
 *
 * Allow        : command is safe, shell proceeds normally
 * Warn(reason) : risky — shell prompts the user to confirm
 * Block        : high risk — shell aborts the command
 */
enum Verdict {
    Allow;
    Warn(reason:String);
    Block;
}

/**
 * AnalysisResult — returned by the command analysis callback
 * passed to UnixSocketServer.
 */
typedef AnalysisResult = {
    var verdict:Verdict;
    var reason:String;
}
