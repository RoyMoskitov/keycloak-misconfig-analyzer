package scanners.keycloak_security.api

data class ScanForm(
    var serverUrl: String = "",
    var realm: String = "",
    var username: String = "",
    var password: String = "",
    var clientId: String = ""
)
