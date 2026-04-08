package scanners.keycloak_security.persistence.dto

import java.time.Instant

data class ScanReportSummaryDto(
    val scanId: String,
    val target: String,
    val realm: String,
    val startedAt: Instant,
    val finishedAt: Instant?,
    val totalChecks: Int,
    val detected: Int,
    val ok: Int,
    val errors: Int
)
