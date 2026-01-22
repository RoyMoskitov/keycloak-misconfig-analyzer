package scanners.keycloak_security.infra

import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import scanners.keycloak_security.domain.model.ScanReport
import scanners.keycloak_security.usecase.checks.KeycloakScanner

@RestController
@RequestMapping("/scan")
class ScanController(
    private val scanner: KeycloakScanner
) {

    data class ScanRequest(
        val serverUrl: String,
        val realm: String,
        val username: String,
        val password: String,
        val clientId: String,
    )

    @PostMapping("/scan")
    fun scan(): ScanReport {
        return scanner.scan()
    }

    @PostMapping("/scan-with-params")
    fun scanWithParams(@RequestBody request: ScanRequest): ScanReport {
        return scanner.scanWithParams(request.serverUrl, request.realm, request.clientId, request.username, request.password)
    }
}
