package scanners.keycloak_security.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "keycloak-audit")
data class KeycloakConnectionProperties(
    var serverUrl: String = "http://localhost:8180",
    var realm: String = "master",
    var authRealm: String = "",     // realm для аутентификации (если пусто — используется master)
    var clientId: String = "admin-cli",
    var username: String = "",
    var password: String = "",
    var clientSecret: String = "",
    var grantType: String = "password"
)
