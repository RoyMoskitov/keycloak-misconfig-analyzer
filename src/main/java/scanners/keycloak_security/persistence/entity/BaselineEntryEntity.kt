package scanners.keycloak_security.persistence.entity

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(
    name = "baseline_entries",
    indexes = [Index(name = "idx_baseline_entry_key", columnList = "checkId,realm,clientId,title")]
)
class BaselineEntryEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    val id: String? = null,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "baseline_id", nullable = false)
    val baseline: BaselineEntity? = null,

    val checkId: String = "",
    val realm: String? = null,
    val clientId: String? = null,
    val title: String = "",

    @Enumerated(EnumType.STRING)
    val status: BaselineStatus = BaselineStatus.ACCEPTED_RISK,

    @Column(length = 2000)
    val justification: String? = null,
    val expiresAt: Instant? = null,
    val createdAt: Instant = Instant.now(),
    val createdBy: String? = null
)
