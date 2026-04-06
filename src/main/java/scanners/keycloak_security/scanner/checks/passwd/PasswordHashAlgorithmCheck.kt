package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class PasswordHashAlgorithmCheck : SecurityCheck {

    override fun id() = "11.4.2"
    override fun title() = "Алгоритм хеширования паролей"
    override fun description() =
        "Проверка использования стойкого алгоритма хеширования (ASVS 11.4.2)"
    override fun severity() = Severity.HIGH

    companion object {
        // Рекомендуемые алгоритмы (OWASP Password Storage Cheat Sheet 2024)
        val RECOMMENDED = setOf("argon2")
        val ACCEPTABLE = setOf("bcrypt", "pbkdf2-sha512", "pbkdf2-sha256")
        val ALL_ALLOWED = RECOMMENDED + ACCEPTABLE

        // Дефолт Keycloak 21+ — pbkdf2-sha256 с 27500 итерациями
        const val KEYCLOAK_DEFAULT_ALGORITHM = "pbkdf2-sha256"
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val policy = context.adminService.getRealm().passwordPolicy

        val algorithm = policy
            ?.let { Regex("hashAlgorithm\\(([^)]+)\\)").find(it) }
            ?.groupValues?.get(1)

        // Если алгоритм не указан явно, Keycloak использует дефолт (pbkdf2-sha256)
        val effectiveAlgorithm = algorithm ?: KEYCLOAK_DEFAULT_ALGORITHM

        when {
            effectiveAlgorithm !in ALL_ALLOWED -> {
                findings += Finding(
                    id = id(),
                    title = title(),
                    description = "Используется небезопасный алгоритм хеширования: '$effectiveAlgorithm'.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("hashAlgorithm", effectiveAlgorithm),
                        Evidence("explicitlyConfigured", algorithm != null),
                        Evidence("allowedAlgorithms", ALL_ALLOWED.joinToString())
                    ),
                    recommendation = "Используйте Argon2id (предпочтительно), bcrypt или PBKDF2-SHA512"
                )
            }
            effectiveAlgorithm in ACCEPTABLE && effectiveAlgorithm !in RECOMMENDED -> {
                findings += Finding(
                    id = id(),
                    title = "Алгоритм хеширования допустим, но не оптимален",
                    description = "Используется '$effectiveAlgorithm'. Алгоритм безопасен, " +
                            "но Argon2id обеспечивает лучшую защиту от GPU-атак благодаря " +
                            "memory-hard свойству.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("hashAlgorithm", effectiveAlgorithm),
                        Evidence("explicitlyConfigured", algorithm != null),
                        Evidence("recommended", RECOMMENDED.joinToString())
                    ),
                    recommendation = "Рассмотрите переход на Argon2id для лучшей защиты от GPU-атак"
                )
            }
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
