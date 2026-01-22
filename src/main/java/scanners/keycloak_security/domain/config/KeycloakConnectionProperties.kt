package scanners.keycloak_security.domain.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "keycloak-audit")
data class KeycloakConnectionProperties(
    var serverUrl: String = "http://localhost:8180",
    var realm: String = "master",
    var clientId: String = "service-account",
    var username: String = "admin",
    var password: String = "6e9NgbJPXKEvaCadnEDrmnFPJbdjiuOk",
    var verifySsl: Boolean = true
)

