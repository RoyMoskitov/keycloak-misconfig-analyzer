package scanners.keycloak_security.scanner.attack

/**
 * Описание вектора атаки из MITRE CAPEC, маппированного на проверки сканера.
 */
data class AttackVector(
    val capecId: String,
    val name: String,
    val description: String,
    val attckTechnique: String,
    val severity: AttackSeverity,
    val prerequisites: List<String>,
    val requiredCheckIds: Set<String>
)

enum class AttackSeverity { CRITICAL, HIGH, MEDIUM, LOW }

/**
 * Результат анализа — активный вектор атаки с доказательствами.
 */
data class ActiveAttackVector(
    val vector: AttackVector,
    val triggeredCheckIds: Set<String>,
    val coveragePercent: Int,
    val status: AttackStatus
)

enum class AttackStatus {
    FULLY_ENABLED,
    PARTIALLY_ENABLED,
    MITIGATED
}
