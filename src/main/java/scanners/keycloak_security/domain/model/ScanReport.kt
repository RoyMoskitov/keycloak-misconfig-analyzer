package scanners.keycloak_security.domain.model

data class ScanReport(
    val scanId: String,
    val target: String,
    val startedAt: String,
    val finishedAt: String?,
    val results: List<CheckResult> = emptyList(),
    val summary: Summary = Summary()
)

data class Summary(
    val totalChecks: Int = 0,
    val detected: Int = 0,
    val ok: Int = 0,
    val errors: Int = 0
)
