package scanners.keycloak_security.api

import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import scanners.keycloak_security.model.ScanReport
import scanners.keycloak_security.scanner.KeycloakScanner

@RestController
@RequestMapping("/api")
class ScanController(
    private val scanner: KeycloakScanner
) {

    @PostMapping("/scan")
    fun scan(): ScanReport {
        return scanner.scan()
    }

    @PostMapping("/scan-with-params")
    fun scanWithParams(@RequestBody request: ScanForm): ScanReport {
        return scanner.scanWithParams(
            request.serverUrl, request.realm, request.clientId,
            request.username, request.password
        )
    }
}
