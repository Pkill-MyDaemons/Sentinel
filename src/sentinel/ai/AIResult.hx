package sentinel.ai;

import sentinel.core.RiskLevel;

/**
 * AIResult — the structured response from any AI analysis call.
 * Returned by AIEngine.analyzeCommand(), analyzeRepo(), etc.
 */
typedef AIResult = {
    /** 0.0 = definitely safe, 1.0 = definitely malicious */
    var riskScore:Float;
    var riskLevel:RiskLevel;
    var summary:String;
    var warnings:Array<String>;
    var recommendation:String;
    /** Raw model response for logging/debugging */
    var rawResponse:String;
}
