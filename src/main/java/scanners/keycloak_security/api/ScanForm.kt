package scanners.keycloak_security.api

data class ScanForm(
    var serverUrl: String = "",
    var realm: String = "",
    var authRealm: String = "",
    var clientId: String = "",
    var grantType: String = "password",
    var username: String = "",
    var password: String = "",
    var clientSecret: String = ""
)
