package scanners.keycloak_security.persistence.repository

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import scanners.keycloak_security.persistence.entity.BaselineEntity

@Repository
interface BaselineRepository : JpaRepository<BaselineEntity, String>
