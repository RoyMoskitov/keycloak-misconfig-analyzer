package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordHashAlgorithmCheck : SecurityCheck {

    override fun id() = "11.4.2"
    override fun title() = "Алгоритм хеширования паролей"
    override fun description() =
        "Проверка использования стойкого алгоритма хеширования (ASVS 11.4.2)"
    override fun severity() = Severity.HIGH

    private val allowed = setOf("argon2", "bcrypt", "pbkdf2-sha512")

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val policy = context.adminService.getRealm().passwordPolicy

        val algorithm = policy
            ?.let { Regex("hashAlgorithm\\(([^)]+)\\)").find(it) }
            ?.groupValues?.get(1)

        return if (algorithm == null || algorithm !in allowed) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Используется небезопасный алгоритм хеширования паролей",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("hashAlgorithm", algorithm)),
                        recommendation = "Используйте Argon2id, bcrypt или pbkdf2-sha512"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}
