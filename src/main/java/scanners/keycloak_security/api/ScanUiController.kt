package scanners.keycloak_security.api

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*
import scanners.keycloak_security.persistence.BaselineService
import scanners.keycloak_security.persistence.ScanDiffService
import scanners.keycloak_security.persistence.ScanPersistenceService
import scanners.keycloak_security.persistence.entity.BaselineStatus
import scanners.keycloak_security.scanner.KeycloakScanner
import scanners.keycloak_security.scanner.SarifExporter
import scanners.keycloak_security.scanner.attack.AttackVectorAnalyzer

@Controller
class ScanUiController(
    private val scanner: KeycloakScanner,
    private val persistenceService: ScanPersistenceService,
    private val diffService: ScanDiffService,
    private val baselineService: BaselineService,
    private val attackAnalyzer: AttackVectorAnalyzer,
    private val sarifExporter: SarifExporter
) {

    @GetMapping("/")
    fun scanForm(model: Model): String {
        model.addAttribute("scanForm", ScanForm())
        return "scan-form"
    }

    @PostMapping("/scan")
    fun runScan(@ModelAttribute scanForm: ScanForm, model: Model): String {
        val report = scanner.scanWithParams(
            serverUrl = scanForm.serverUrl,
            realm = scanForm.realm,
            clientId = scanForm.clientId,
            username = scanForm.username,
            password = scanForm.password,
            clientSecret = scanForm.clientSecret,
            grantType = scanForm.grantType,
            authRealm = scanForm.authRealm
        )
        val attacks = attackAnalyzer.analyze(report)

        model.addAttribute("report", report)
        model.addAttribute("attacks", attacks)
        model.addAttribute("scanForm", scanForm)
        return "scan-result"
    }

    @GetMapping("/history")
    fun history(model: Model): String {
        model.addAttribute("scans", persistenceService.findAll())
        return "history"
    }

    @GetMapping("/history/{scanId}")
    fun scanDetail(@PathVariable scanId: String, model: Model): String {
        val report = persistenceService.findById(scanId) ?: return "redirect:/history"
        val attacks = attackAnalyzer.analyze(report)
        model.addAttribute("report", report)
        model.addAttribute("attacks", attacks)
        return "scan-result"
    }

    @GetMapping("/diff")
    fun diffForm(model: Model): String {
        model.addAttribute("scans", persistenceService.findAll())
        return "diff"
    }

    @GetMapping("/diff/result")
    fun diffResult(
        @RequestParam baseScanId: String,
        @RequestParam compareScanId: String,
        model: Model
    ): String {
        val diff = diffService.diff(baseScanId, compareScanId)
        model.addAttribute("diff", diff)
        return "diff-result"
    }

    // --- Baseline ---

    @GetMapping("/baselines")
    fun baselines(model: Model): String {
        model.addAttribute("baselines", baselineService.listBaselines())
        model.addAttribute("scans", persistenceService.findAll())
        return "baselines"
    }

    @PostMapping("/baselines/create")
    fun createBaseline(
        @RequestParam scanId: String,
        @RequestParam name: String,
        @RequestParam status: BaselineStatus
    ): String {
        baselineService.createFromScan(scanId, name, status)
        return "redirect:/baselines"
    }

    @GetMapping("/baselines/{baselineId}/apply")
    fun applyBaseline(
        @PathVariable baselineId: String,
        @RequestParam scanId: String,
        model: Model
    ): String {
        val filteredReport = baselineService.getFilteredReport(scanId, baselineId)
        model.addAttribute("filtered", filteredReport)
        return "baseline-report"
    }
}
