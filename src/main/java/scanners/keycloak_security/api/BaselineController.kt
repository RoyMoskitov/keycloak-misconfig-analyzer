package scanners.keycloak_security.api

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import scanners.keycloak_security.persistence.BaselineService
import scanners.keycloak_security.persistence.dto.AddBaselineEntryRequest
import scanners.keycloak_security.persistence.dto.FilteredScanReport
import scanners.keycloak_security.persistence.entity.BaselineStatus

@RestController
@RequestMapping("/api/baselines")
class BaselineController(
    private val baselineService: BaselineService
) {

    @PostMapping("/from-scan/{scanId}")
    fun createFromScan(
        @PathVariable scanId: String,
        @RequestParam name: String,
        @RequestParam(defaultValue = "ACCEPTED_RISK") status: BaselineStatus
    ): BaselineDto {
        val entity = baselineService.createFromScan(scanId, name, status)
        return entity.toDto()
    }

    @GetMapping
    fun listBaselines(): List<BaselineDto> =
        baselineService.listBaselines().map { it.toDto() }

    @GetMapping("/{baselineId}")
    fun getBaseline(@PathVariable baselineId: String): ResponseEntity<BaselineDto> =
        baselineService.getBaseline(baselineId)
            ?.let { ResponseEntity.ok(it.toDto()) }
            ?: ResponseEntity.notFound().build()

    @PostMapping("/{baselineId}/entries")
    fun addEntry(
        @PathVariable baselineId: String,
        @RequestBody request: AddBaselineEntryRequest
    ): ResponseEntity<Void> {
        baselineService.addEntry(baselineId, request)
        return ResponseEntity.ok().build()
    }

    @DeleteMapping("/entries/{entryId}")
    fun removeEntry(@PathVariable entryId: String): ResponseEntity<Void> {
        baselineService.removeEntry(entryId)
        return ResponseEntity.noContent().build()
    }

    @GetMapping("/filtered-report")
    fun getFilteredReport(
        @RequestParam scanId: String,
        @RequestParam baselineId: String
    ): FilteredScanReport = baselineService.getFilteredReport(scanId, baselineId)

    // DTO to avoid Jackson infinite recursion on entity references
    data class BaselineDto(
        val id: String?,
        val name: String,
        val sourceScanId: String?,
        val createdAt: String,
        val entriesCount: Int
    )

    private fun scanners.keycloak_security.persistence.entity.BaselineEntity.toDto() = BaselineDto(
        id = id,
        name = name,
        sourceScanId = sourceScanId,
        createdAt = createdAt.toString(),
        entriesCount = entries.size
    )
}
