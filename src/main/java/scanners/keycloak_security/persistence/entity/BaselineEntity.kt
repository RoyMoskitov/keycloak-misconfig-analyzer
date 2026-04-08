package scanners.keycloak_security.persistence.entity

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "baselines")
class BaselineEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    val id: String? = null,

    val name: String = "",
    val createdAt: Instant = Instant.now(),
    val sourceScanId: String? = null,

    @OneToMany(mappedBy = "baseline", cascade = [CascadeType.ALL], orphanRemoval = true, fetch = FetchType.LAZY)
    val entries: MutableList<BaselineEntryEntity> = mutableListOf()
)
