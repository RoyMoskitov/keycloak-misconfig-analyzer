package scanners.keycloak_security.domain.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "keycloak-audit")
data class KeycloakConnectionProperties(
    var serverUrl: String = "http://localhost:8180",
    var realm: String = "master",
    var clientId: String = "admin-cli",
    var username: String = "admin",
    var password: String = "adminpass",
    var verifySsl: Boolean = true
)

