package scanners.keycloak_security.persistence.repository

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import scanners.keycloak_security.persistence.entity.ScanReportEntity

@Repository
interface ScanReportRepository : JpaRepository<ScanReportEntity, String> {
    fun findAllByOrderByStartedAtDesc(): List<ScanReportEntity>
}
