package scanners.keycloak_security.persistence

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import scanners.keycloak_security.persistence.dto.*
import scanners.keycloak_security.persistence.entity.*
import scanners.keycloak_security.persistence.repository.BaselineRepository
import scanners.keycloak_security.persistence.repository.ScanFindingRepository
import java.time.Instant

@Service
@Transactional
class BaselineService(
    private val baselineRepo: BaselineRepository,
    private val findingRepo: ScanFindingRepository,
    private val mapper: ScanReportMapper
) {

    fun createFromScan(scanId: String, name: String, statusForAll: BaselineStatus): BaselineEntity {
        val findings = findingRepo.findByReportScanId(scanId)
        val baseline = BaselineEntity(name = name, sourceScanId = scanId)

        findings.forEach { finding ->
            baseline.entries += BaselineEntryEntity(
                baseline = baseline,
                checkId = finding.checkId,
                realm = finding.realm,
                clientId = finding.clientId,
                title = finding.title,
                status = statusForAll,
                justification = "Imported from scan $scanId"
            )
        }

        return baselineRepo.save(baseline)
    }

    fun addEntry(baselineId: String, request: AddBaselineEntryRequest): BaselineEntryEntity {
        val baseline = baselineRepo.findById(baselineId)
            .orElseThrow { IllegalArgumentException("Baseline $baselineId not found") }

        val entry = BaselineEntryEntity(
            baseline = baseline,
            checkId = request.checkId,
            realm = request.realm,
            clientId = request.clientId,
            title = request.title,
            status = request.status,
            justification = request.justification,
            expiresAt = request.expiresAt
        )

        baseline.entries += entry
        baselineRepo.save(baseline)
        return entry
    }

    fun removeEntry(entryId: String) {
        baselineRepo.findAll().forEach { baseline ->
            baseline.entries.removeIf { it.id == entryId }
            baselineRepo.save(baseline)
        }
    }

    @Transactional(readOnly = true)
    fun listBaselines(): List<BaselineEntity> = baselineRepo.findAll()

    @Transactional(readOnly = true)
    fun getBaseline(baselineId: String): BaselineEntity? =
        baselineRepo.findById(baselineId).orElse(null)

    @Transactional(readOnly = true)
    fun getFilteredReport(scanId: String, baselineId: String): FilteredScanReport {
        val findings = findingRepo.findByReportScanId(scanId)
        val baseline = baselineRepo.findById(baselineId)
            .orElseThrow { IllegalArgumentException("Baseline $baselineId not found") }

        val now = Instant.now()

        // Собираем активные записи baseline (не expired)
        val activeEntries = baseline.entries.filter { entry ->
            when {
                entry.status == BaselineStatus.DEFERRED && entry.expiresAt != null ->
                    entry.expiresAt.isAfter(now) // ещё не истёк
                else -> true
            }
        }

        val baselineKeys = activeEntries.map { FindingKey(it.checkId, it.realm, it.clientId, it.title) }.toSet()
        val entryByKey = activeEntries.associateBy { FindingKey(it.checkId, it.realm, it.clientId, it.title) }

        val actionable = mutableListOf<scanners.keycloak_security.model.Finding>()
        val baselined = mutableListOf<BaselinedFinding>()

        findings.forEach { entity ->
            val key = FindingKey(entity.checkId, entity.realm, entity.clientId, entity.title)
            val finding = mapper.toFinding(entity)

            if (key in baselineKeys) {
                val entry = entryByKey[key]!!
                baselined += BaselinedFinding(
                    finding = finding,
                    baselineStatus = entry.status,
                    justification = entry.justification,
                    expiresAt = entry.expiresAt
                )
            } else {
                actionable += finding
            }
        }

        return FilteredScanReport(
            scanId = scanId,
            baselineId = baselineId,
            actionableFindings = actionable,
            baselinedFindings = baselined,
            summary = FilteredSummary(
                totalFindings = findings.size,
                actionable = actionable.size,
                acceptedRisk = baselined.count { it.baselineStatus == BaselineStatus.ACCEPTED_RISK },
                falsePositive = baselined.count { it.baselineStatus == BaselineStatus.FALSE_POSITIVE },
                deferred = baselined.count { it.baselineStatus == BaselineStatus.DEFERRED }
            )
        )
    }

    private data class FindingKey(val checkId: String, val realm: String?, val clientId: String?, val title: String)
}
