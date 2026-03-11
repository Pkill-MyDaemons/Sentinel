package sentinel.ai;

using StringTools;

import sentinel.ai.RepoData;
import haxe.Json;
import haxe.Http;
import sentinel.core.Logger;

/**
 * GitHubFetcher — retrieves repository metadata and critical files
 * for security analysis.
 *
 * Fetches:
 *   - Repo metadata (stars, forks, age, owner info)
 *   - README.md
 *   - install.sh / install.bash / setup.sh
 *   - Brewfile / Formula/*.rb (for brew tap analysis)
 *   - package.json / requirements.txt / Makefile
 *   - Top-level file listing
 */
class GitHubFetcher {

    static final API = "https://api.github.com";
    static final RAW = "https://raw.githubusercontent.com";

    var token:String;

    public function new(?token:String) {
        this.token = token ?? "";
    }

    /**
     * Given a brew tap command like `brew tap evil/tap` or a github URL,
     * extract owner/repo and fetch full repo data.
     */
    public function fetchForCommand(cmd:String):{ url:String, data:RepoData } {
        var parsed = parseRepoFromCommand(cmd);
        if (parsed == null) throw 'Could not extract GitHub repo from: $cmd';
        return { url: parsed, data: fetch(parsed) };
    }

    public function fetch(repoUrl:String):RepoData {
        var ownerRepo = extractOwnerRepo(repoUrl);
        if (ownerRepo == null) throw 'Invalid GitHub URL: $repoUrl';

        var owner = ownerRepo.owner;
        var repo  = ownerRepo.repo;

        Logger.info('[GitHub] Fetching $owner/$repo...');

        // Repo metadata
        var meta = apiGet('/repos/$owner/$repo');
        var ownerMeta = apiGet('/users/$owner');

        // File listing (top-level)
        var tree = apiGet('/repos/$owner/$repo/git/trees/HEAD?recursive=0');
        var files:Array<String> = [];
        if (tree != null && tree.tree != null) {
            for (f in (tree.tree:Array<Dynamic>)) {
                if (f.type == "blob") files.push(f.path);
            }
        }

        // Fetch key files
        var readme       = tryFetchRaw(owner, repo, "README.md");
        var installSh    = tryFetchRaw(owner, repo, "install.sh")
                        ?? tryFetchRaw(owner, repo, "install.bash")
                        ?? tryFetchRaw(owner, repo, "setup.sh");
        var packageJson  = tryFetchRaw(owner, repo, "package.json");
        var makefile     = tryFetchRaw(owner, repo, "Makefile");
        var brewFormula  = findBrewFormula(owner, repo, files);

        // Combine install script info
        var installScript = "";
        if (installSh != null) installScript += "=== install.sh ===\n" + installSh.substr(0, 3000) + "\n";
        if (makefile != null)  installScript += "=== Makefile ===\n" + makefile.substr(0, 1000) + "\n";
        if (brewFormula != null) installScript += "=== Formula ===\n" + brewFormula.substr(0, 2000) + "\n";

        // Calculate owner account age
        var ownerAge = "unknown";
        if (ownerMeta != null && ownerMeta.created_at != null) {
            ownerAge = ownerMeta.created_at;
        }

        return {
            readme: readme,
            installScript: installScript.length > 0 ? installScript : null,
            packageJson: packageJson,
            fileList: files,
            stars:     meta != null ? Std.int(meta.stargazers_count) : 0,
            forks:     meta != null ? Std.int(meta.forks_count) : 0,
            createdAt: meta != null ? meta.created_at : "unknown",
            pushedAt:  meta != null ? meta.pushed_at : "unknown",
            ownerAge:  ownerAge,
        };
    }

    // ----------------------------------------------------------------
    // Parsing helpers
    // ----------------------------------------------------------------

    /**
     * Extract GitHub repo URL from terminal commands like:
     *   brew tap owner/repo
     *   brew install owner/repo/formula
     *   curl https://raw.githubusercontent.com/owner/repo/...
     *   git clone https://github.com/owner/repo
     *   bash <(curl https://raw.githubusercontent.com/owner/repo/...)
     */
    public static function parseRepoFromCommand(cmd:String):Null<String> {
        // brew tap owner/repo
        var tapRe = ~/brew\s+tap\s+([\w.-]+)\/([\w.-]+)/;
        if (tapRe.match(cmd)) {
            return 'https://github.com/${tapRe.matched(1)}/${tapRe.matched(2)}';
        }

        // github.com/owner/repo anywhere in command
        var ghRe = ~/github\.com\/([\w.-]+)\/([\w.-]+)/;
        if (ghRe.match(cmd)) {
            return 'https://github.com/${ghRe.matched(1)}/${ghRe.matched(2)}';
        }

        // raw.githubusercontent.com/owner/repo
        var rawRe = ~/raw\.githubusercontent\.com\/([\w.-]+)\/([\w.-]+)/;
        if (rawRe.match(cmd)) {
            return 'https://github.com/${rawRe.matched(1)}/${rawRe.matched(2)}';
        }

        return null;
    }

    static function extractOwnerRepo(url:String):Null<{ owner:String, repo:String }> {
        var re = ~/github\.com\/([\w.-]+)\/([\w.-]+)/;
        if (!re.match(url)) return null;
        var repo = re.matched(2);
        // Strip .git suffix if present
        if (repo.endsWith(".git")) repo = repo.substr(0, repo.length - 4);
        return { owner: re.matched(1), repo: repo };
    }

    function findBrewFormula(owner:String, repo:String, files:Array<String>):Null<String> {
        for (f in files) {
            if (f.startsWith("Formula/") && f.endsWith(".rb")) {
                return tryFetchRaw(owner, repo, f);
            }
        }
        // Also try root-level .rb files
        for (f in files) {
            if (f.endsWith(".rb") && !f.contains("/")) {
                return tryFetchRaw(owner, repo, f);
            }
        }
        return null;
    }

    // ----------------------------------------------------------------
    // HTTP helpers
    // ----------------------------------------------------------------

    function apiGet(path:String):Dynamic {
        var http = new Http(API + path);
        http.setHeader("Accept", "application/vnd.github+json");
        http.setHeader("User-Agent", "Sentinel-Security/0.1");
        if (token != "") http.setHeader("Authorization", "Bearer " + token);

        var response = "";
        var error = "";
        http.onData = (d) -> response = d;
        http.onError = (e) -> error = e;
        http.request(false);

        if (error != "") {
            Logger.warn('[GitHub] API error for $path: $error');
            return null;
        }
        try {
            return Json.parse(response);
        } catch (e:Dynamic) {
            Logger.warn('[GitHub] JSON parse error for $path: $e');
            return null;
        }
    }

    function tryFetchRaw(owner:String, repo:String, file:String):Null<String> {
        var url = '$RAW/$owner/$repo/HEAD/$file';
        var http = new Http(url);
        if (token != "") http.setHeader("Authorization", "Bearer " + token);
        http.setHeader("User-Agent", "Sentinel-Security/0.1");

        var response = "";
        var error = "";
        http.onData = (d) -> response = d;
        http.onError = (e) -> error = e;
        http.request(false);

        if (error != "" || response == "") return null;
        return response;
    }
}
