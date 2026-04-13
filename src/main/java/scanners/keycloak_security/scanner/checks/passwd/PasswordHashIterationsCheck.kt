package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class PasswordHashIterationsCheck : SecurityCheck {

    override fun id() = "11.4.3"
    override fun title() = "Work factor хеширования пароля"
    override fun description() = "Проверка достаточного количества итераций хеширования с учётом алгоритма (ASVS 11.4.3)"
    override fun severity() = Severity.MEDIUM

    companion object {
        // Минимальные рекомендации OWASP Password Storage Cheat Sheet (2024)
        val MIN_ITERATIONS_BY_ALGORITHM = mapOf(
            "pbkdf2-sha256" to 600_000,
            "pbkdf2-sha512" to 210_000,
            "pbkdf2" to 600_000,       // без указания хеша — считаем SHA-256
            "bcrypt" to 10,            // cost factor, не итерации
            "argon2" to 2              // итерации Argon2 — обычно 2-3 при достаточной памяти
        )

        // Keycloak 21+ дефолт: pbkdf2-sha256 с 27500 итерациями
        const val KEYCLOAK_DEFAULT_ITERATIONS = 27_500
        const val KEYCLOAK_DEFAULT_ALGORITHM = "pbkdf2-sha256"
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val policy = context.adminService.getRealm().passwordPolicy

        val iterations = policy
            ?.let { Regex("hashIterations\\((\\d+)\\)").find(it) }
            ?.groupValues?.get(1)?.toInt()

        val algorithm = policy
            ?.let { Regex("hashAlgorithm\\(([^)]+)\\)").find(it) }
            ?.groupValues?.get(1)
            ?: KEYCLOAK_DEFAULT_ALGORITHM

        val effectiveIterations = iterations ?: KEYCLOAK_DEFAULT_ITERATIONS
        val minRequired = MIN_ITERATIONS_BY_ALGORITHM[algorithm]

        if (minRequired != null && effectiveIterations < minRequired) {
            val algorithmLabel = when (algorithm) {
                "bcrypt" -> "cost factor"
                else -> "итераций"
            }

            findings += Finding(
                id = id(),
                title = title(),
                description = "Для алгоритма '$algorithm' используется $effectiveIterations $algorithmLabel, " +
                        "рекомендуемый минимум — $minRequired. " +
                        "Недостаточное количество итераций ускоряет офлайн-перебор при утечке хешей.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("hashAlgorithm", algorithm),
                    Evidence("hashIterations", effectiveIterations),
                    Evidence("explicitlyConfigured", iterations != null),
                    Evidence("recommendedMinimum", minRequired)
                ),
                recommendation = "Установите hashIterations($minRequired) в Password Policy " +
                        "или рассмотрите переход на Argon2id"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
