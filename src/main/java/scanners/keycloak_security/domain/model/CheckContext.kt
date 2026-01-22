package scanners.keycloak_security.domain.model

import scanners.keycloak_security.usecase.checks.KeycloakAdminService

data class CheckContext(
    val realmName: String,
    val adminService: KeycloakAdminService
)
