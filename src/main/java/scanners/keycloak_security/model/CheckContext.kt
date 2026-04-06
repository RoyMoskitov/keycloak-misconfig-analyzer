package scanners.keycloak_security.model

import scanners.keycloak_security.service.KeycloakAdminService

data class CheckContext(
    val realmName: String,
    val adminService: KeycloakAdminService
)
