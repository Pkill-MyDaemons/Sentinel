package sentinel.ai;

using StringTools;

/**
 * RepoData — structured result of a GitHub repository fetch.
 * Populated by GitHubFetcher, consumed by AIEngine.analyzeRepo().
 */
typedef RepoData = {
    @:optional var readme:String;
    @:optional var installScript:String;
    @:optional var packageJson:String;
    @:optional var fileList:Array<String>;
    var stars:Int;
    var forks:Int;
    var createdAt:String;
    var pushedAt:String;
    var ownerAge:String;
}
