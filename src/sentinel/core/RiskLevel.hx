package sentinel.core;

/**
 * RiskLevel — severity classification used across all Sentinel modules.
 * Returned by AIEngine analysis methods and carried by SecurityEvents.
 */
enum RiskLevel {
    Safe;
    Low;
    Medium;
    High;
    Critical;
}
