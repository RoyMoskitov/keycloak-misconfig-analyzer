package scanners.keycloak_security.persistence

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import scanners.keycloak_security.model.ScanReport
import scanners.keycloak_security.persistence.dto.ScanReportSummaryDto
import scanners.keycloak_security.persistence.repository.ScanReportRepository

@Service
@Transactional
class ScanPersistenceService(
    private val reportRepo: ScanReportRepository,
    private val mapper: ScanReportMapper
) {

    fun save(report: ScanReport, realm: String) {
        val entity = mapper.toEntity(report, realm)
        reportRepo.save(entity)
    }

    @Transactional(readOnly = true)
    fun findAll(): List<ScanReportSummaryDto> {
        return reportRepo.findAllByOrderByStartedAtDesc().map { mapper.toSummaryDto(it) }
    }

    @Transactional(readOnly = true)
    fun findById(scanId: String): ScanReport? {
        return reportRepo.findById(scanId).map { mapper.toModel(it) }.orElse(null)
    }

    fun delete(scanId: String) {
        reportRepo.deleteById(scanId)
    }
}
