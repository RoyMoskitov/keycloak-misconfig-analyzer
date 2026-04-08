package scanners.keycloak_security.persistence.repository

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import scanners.keycloak_security.persistence.entity.ScanFindingEntity

@Repository
interface ScanFindingRepository : JpaRepository<ScanFindingEntity, String> {
    fun findByReportScanId(scanId: String): List<ScanFindingEntity>
}
