package scanners.keycloak_security.domain.model

enum class Severity { LOW, MEDIUM, HIGH, INFO }

enum class CheckStatus { DETECTED, OK, ERROR, WARNING, INFO }

data class Evidence(val key: String, val value: Any?)

data class Finding(
    val id: String,
    val title: String,
    val description: String,
    val severity: Severity,
    val status: CheckStatus,
    var realm: String? = null,
    val clientId: String? = null,
    val evidence: List<Evidence> = emptyList(),
    val recommendation: String? = null
)

data class CheckResult(
    val checkId: String,
    val status: CheckStatus,
    val findings: List<Finding> = emptyList(),
    val durationMs: Long = 0,
    val error: String? = null
)