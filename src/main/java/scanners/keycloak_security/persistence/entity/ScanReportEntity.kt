package scanners.keycloak_security.persistence.entity

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "scan_reports")
class ScanReportEntity(
    @Id
    val scanId: String = "",

    val target: String = "",
    val realm: String = "",
    val startedAt: Instant = Instant.now(),
    val finishedAt: Instant? = null,

    val totalChecks: Int = 0,
    val detected: Int = 0,
    val ok: Int = 0,
    val errors: Int = 0,

    @OneToMany(mappedBy = "report", cascade = [CascadeType.ALL], orphanRemoval = true, fetch = FetchType.LAZY)
    val findings: MutableList<ScanFindingEntity> = mutableListOf()
)
