package scanners.keycloak_security.api

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*
import scanners.keycloak_security.model.ScanReport
import scanners.keycloak_security.scanner.KeycloakScanner

@Controller
@RequestMapping("/")
class ScanUiController(
    private val scanner: KeycloakScanner
) {

    @GetMapping
    fun scanForm(model: Model): String {
        model.addAttribute("scanForm", ScanForm())
        return "scan-form"
    }

    @PostMapping("/scan")
    fun runScan(
        @ModelAttribute scanForm: ScanForm,
        model: Model
    ): String {

        val report = scanner.scanWithParams(
            scanForm.serverUrl,
            scanForm.realm,
            scanForm.clientId,
            scanForm.username,
            scanForm.password
        )

        model.addAttribute("report", report)
        return "scan-result"
    }
}
