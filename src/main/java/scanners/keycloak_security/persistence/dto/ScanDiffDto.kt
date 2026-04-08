package scanners.keycloak_security.persistence.dto

import scanners.keycloak_security.model.Finding

data class ScanDiffDto(
    val baseScanId: String,
    val compareScanId: String,
    val newFindings: List<Finding>,
    val resolvedFindings: List<Finding>,
    val unchangedFindings: List<Finding>
)
