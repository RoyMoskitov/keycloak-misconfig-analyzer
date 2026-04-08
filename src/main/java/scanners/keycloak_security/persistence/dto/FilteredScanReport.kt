package scanners.keycloak_security.persistence.dto

import scanners.keycloak_security.model.Finding
import scanners.keycloak_security.persistence.entity.BaselineStatus
import java.time.Instant

data class FilteredScanReport(
    val scanId: String,
    val baselineId: String,
    val actionableFindings: List<Finding>,
    val baselinedFindings: List<BaselinedFinding>,
    val summary: FilteredSummary
)

data class BaselinedFinding(
    val finding: Finding,
    val baselineStatus: BaselineStatus,
    val justification: String?,
    val expiresAt: Instant?
)

data class FilteredSummary(
    val totalFindings: Int,
    val actionable: Int,
    val acceptedRisk: Int,
    val falsePositive: Int,
    val deferred: Int
)
