package scanners.keycloak_security.api

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import scanners.keycloak_security.model.ScanReport
import scanners.keycloak_security.persistence.ScanDiffService
import scanners.keycloak_security.persistence.ScanPersistenceService
import scanners.keycloak_security.persistence.dto.ScanDiffDto
import scanners.keycloak_security.persistence.dto.ScanReportSummaryDto
import scanners.keycloak_security.scanner.KeycloakScanner
import scanners.keycloak_security.scanner.SarifExporter
import scanners.keycloak_security.scanner.SarifLog
import scanners.keycloak_security.scanner.attack.ActiveAttackVector
import scanners.keycloak_security.scanner.attack.AttackVectorAnalyzer

@RestController
@RequestMapping("/api")
class ScanController(
    private val scanner: KeycloakScanner,
    private val persistenceService: ScanPersistenceService,
    private val diffService: ScanDiffService,
    private val attackAnalyzer: AttackVectorAnalyzer,
    private val sarifExporter: SarifExporter
) {

    // --- Scan execution ---

    @PostMapping("/scan")
    fun scan(): ScanReport = scanner.scan()

    @PostMapping("/scan-with-params")
    fun scanWithParams(@RequestBody request: ScanForm): ScanReport =
        scanner.scanWithParams(
            serverUrl = request.serverUrl,
            realm = request.realm,
            clientId = request.clientId,
            username = request.username,
            password = request.password,
            clientSecret = request.clientSecret,
            grantType = request.grantType,
            authRealm = request.authRealm
        )

    // --- Scan history (Level 1) ---

    @GetMapping("/scans")
    fun listScans(): List<ScanReportSummaryDto> = persistenceService.findAll()

    @GetMapping("/scans/{scanId}")
    fun getScan(@PathVariable scanId: String): ResponseEntity<ScanReport> =
        persistenceService.findById(scanId)
            ?.let { ResponseEntity.ok(it) }
            ?: ResponseEntity.notFound().build()

    @DeleteMapping("/scans/{scanId}")
    fun deleteScan(@PathVariable scanId: String): ResponseEntity<Void> {
        persistenceService.delete(scanId)
        return ResponseEntity.noContent().build()
    }

    // --- Diff (Level 2) ---

    @GetMapping("/scans/diff")
    fun diff(
        @RequestParam baseScanId: String,
        @RequestParam compareScanId: String
    ): ScanDiffDto = diffService.diff(baseScanId, compareScanId)

    // --- Attack Vector Analysis ---

    @GetMapping("/scans/{scanId}/attacks")
    fun analyzeAttackVectors(@PathVariable scanId: String): ResponseEntity<List<ActiveAttackVector>> {
        val report = persistenceService.findById(scanId)
            ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(attackAnalyzer.analyze(report))
    }

    @PostMapping("/scan-and-analyze")
    fun scanAndAnalyze(): ScanWithAttacksResponse {
        val report = scanner.scan()
        val attacks = attackAnalyzer.analyze(report)
        return ScanWithAttacksResponse(report, attacks)
    }

    @PostMapping("/scan-and-analyze-with-params")
    fun scanAndAnalyzeWithParams(@RequestBody request: ScanForm): ScanWithAttacksResponse {
        val report = scanner.scanWithParams(
            serverUrl = request.serverUrl, realm = request.realm,
            clientId = request.clientId, username = request.username,
            password = request.password, clientSecret = request.clientSecret,
            grantType = request.grantType, authRealm = request.authRealm
        )
        val attacks = attackAnalyzer.analyze(report)
        return ScanWithAttacksResponse(report, attacks)
    }

    data class ScanWithAttacksResponse(
        val report: ScanReport,
        val attackVectors: List<ActiveAttackVector>
    )

    // --- SARIF Export ---

    @GetMapping("/scans/{scanId}/sarif", produces = ["application/json"])
    fun exportSarif(@PathVariable scanId: String): ResponseEntity<SarifLog> {
        val report = persistenceService.findById(scanId)
            ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(sarifExporter.export(report))
    }

    @PostMapping("/scan-sarif", produces = ["application/json"])
    fun scanAndExportSarif(): SarifLog {
        val report = scanner.scan()
        return sarifExporter.export(report)
    }

    @PostMapping("/scan-sarif-with-params", produces = ["application/json"])
    fun scanAndExportSarifWithParams(@RequestBody request: ScanForm): SarifLog {
        val report = scanner.scanWithParams(
            serverUrl = request.serverUrl, realm = request.realm,
            clientId = request.clientId, username = request.username,
            password = request.password, clientSecret = request.clientSecret,
            grantType = request.grantType, authRealm = request.authRealm
        )
        return sarifExporter.export(report)
    }
}
