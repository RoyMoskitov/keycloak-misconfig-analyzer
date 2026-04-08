package scanners.keycloak_security.persistence.dto

import scanners.keycloak_security.persistence.entity.BaselineStatus
import java.time.Instant

data class AddBaselineEntryRequest(
    val checkId: String,
    val realm: String? = null,
    val clientId: String? = null,
    val title: String,
    val status: BaselineStatus,
    val justification: String? = null,
    val expiresAt: Instant? = null
)
