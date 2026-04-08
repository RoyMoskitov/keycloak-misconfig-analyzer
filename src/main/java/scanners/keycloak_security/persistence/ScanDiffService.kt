package scanners.keycloak_security.persistence

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import scanners.keycloak_security.model.Finding
import scanners.keycloak_security.persistence.dto.ScanDiffDto
import scanners.keycloak_security.persistence.entity.ScanFindingEntity
import scanners.keycloak_security.persistence.repository.ScanFindingRepository

@Service
@Transactional(readOnly = true)
class ScanDiffService(
    private val findingRepo: ScanFindingRepository,
    private val mapper: ScanReportMapper
) {

    data class FindingKey(val checkId: String, val realm: String?, val clientId: String?, val title: String)

    fun diff(baseScanId: String, compareScanId: String): ScanDiffDto {
        val baseFindings = findingRepo.findByReportScanId(baseScanId)
        val compareFindings = findingRepo.findByReportScanId(compareScanId)

        val baseMap = baseFindings.associateBy { it.toKey() }
        val compareMap = compareFindings.associateBy { it.toKey() }

        val baseKeys = baseMap.keys
        val compareKeys = compareMap.keys

        val newKeys = compareKeys - baseKeys
        val resolvedKeys = baseKeys - compareKeys
        val unchangedKeys = baseKeys.intersect(compareKeys)

        return ScanDiffDto(
            baseScanId = baseScanId,
            compareScanId = compareScanId,
            newFindings = newKeys.mapNotNull { compareMap[it]?.let { e -> mapper.toFinding(e) } },
            resolvedFindings = resolvedKeys.mapNotNull { baseMap[it]?.let { e -> mapper.toFinding(e) } },
            unchangedFindings = unchangedKeys.mapNotNull { compareMap[it]?.let { e -> mapper.toFinding(e) } }
        )
    }

    private fun ScanFindingEntity.toKey() = FindingKey(checkId, realm, clientId, title)
}
