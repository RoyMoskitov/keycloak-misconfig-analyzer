package scanners.keycloak_security.persistence.entity

import jakarta.persistence.*
import scanners.keycloak_security.model.CheckStatus
import scanners.keycloak_security.model.Severity

@Entity
@Table(
    name = "scan_findings",
    indexes = [
        Index(name = "idx_finding_composite", columnList = "checkId,realm,clientId,title"),
        Index(name = "idx_finding_severity", columnList = "severity")
    ]
)
class ScanFindingEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    val id: String? = null,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    val report: ScanReportEntity? = null,

    val checkId: String = "",
    val title: String = "",

    @Column(length = 4000)
    val description: String = "",

    @Enumerated(EnumType.STRING)
    val severity: Severity = Severity.LOW,

    @Enumerated(EnumType.STRING)
    val status: CheckStatus = CheckStatus.OK,

    val realm: String? = null,
    val clientId: String? = null,

    @Column(length = 2000)
    val recommendation: String? = null,

    @Column(columnDefinition = "CLOB")
    val evidenceJson: String? = null
)
