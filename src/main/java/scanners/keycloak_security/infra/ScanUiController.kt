package scanners.keycloak_security.infra

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*
import scanners.keycloak_security.domain.model.ScanForm
import scanners.keycloak_security.domain.model.ScanReport
import scanners.keycloak_security.usecase.checks.KeycloakScanner

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
