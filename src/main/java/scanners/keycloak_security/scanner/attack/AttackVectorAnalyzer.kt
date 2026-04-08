package scanners.keycloak_security.scanner.attack

import org.springframework.stereotype.Service
import scanners.keycloak_security.model.CheckStatus
import scanners.keycloak_security.model.ScanReport

/**
 * Анализатор векторов атак. Берёт результат скана и определяет,
 * какие атаки из CAPEC возможны на данной конфигурации Keycloak.
 *
 * Логика: для каждой атаки определён набор check IDs (prerequisites).
 * Если findings по этим check IDs обнаружены (status=DETECTED) — атака возможна.
 *
 * coveragePercent = (triggered / required) * 100
 * - 100% → FULLY_ENABLED (все prerequisites выполнены)
 * - ≥50% → PARTIALLY_ENABLED (часть prerequisites)
 * - <50% → MITIGATED
 */
@Service
class AttackVectorAnalyzer {

    fun analyze(report: ScanReport): List<ActiveAttackVector> {
        // Собираем все check IDs со статусом DETECTED
        val detectedCheckIds = report.results
            .filter { it.status == CheckStatus.DETECTED }
            .map { it.checkId }
            .toSet()

        return AttackVectorRegistry.vectors.map { vector ->
            val triggered = vector.requiredCheckIds.intersect(detectedCheckIds)
            val coverage = if (vector.requiredCheckIds.isNotEmpty())
                (triggered.size * 100) / vector.requiredCheckIds.size
            else 0

            val status = when {
                coverage == 100 -> AttackStatus.FULLY_ENABLED
                coverage >= 50 -> AttackStatus.PARTIALLY_ENABLED
                else -> AttackStatus.MITIGATED
            }

            ActiveAttackVector(
                vector = vector,
                triggeredCheckIds = triggered,
                coveragePercent = coverage,
                status = status
            )
        }.sortedWith(
            compareBy<ActiveAttackVector> { it.status.ordinal }
                .thenByDescending { it.coveragePercent }
                .thenByDescending { it.vector.severity.ordinal }
        )
    }
}
