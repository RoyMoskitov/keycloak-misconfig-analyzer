package scanners.keycloak_security.usecase.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.JwtParser
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class JwtSignaturePresenceCheck : SecurityCheck {

    override fun id() = "9.1.1"
    override fun title() = "Наличие криптографической подписи JWT"
    override fun description() =
        "Проверка, что self-contained токены подписываются и не используют alg=none"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            val token = context.adminService.getAccessToken().accessToken
            val header = JwtParser.parseHeader(token)

            val alg = header["alg"]?.toString()

            if (alg == null) {
                findings += Finding(
                    id(),
                    "Алгоритм подписи не указан",
                    "JWT не содержит заголовок 'alg'",
                    Severity.HIGH,
                    CheckStatus.DETECTED,
                    context.realmName,
                    recommendation =
                        "Убедитесь, что токены подписываются с использованием криптографического алгоритма."
                )
            } else if (alg.equals("none", ignoreCase = true)) {
                findings += Finding(
                    id(),
                    "Используется alg=none",
                    "JWT подписан с использованием небезопасного алгоритма 'none'",
                    Severity.HIGH,
                    CheckStatus.DETECTED,
                    context.realmName,
                    evidence = listOf(Evidence("alg", alg)),
                    recommendation =
                        "Запретите использование алгоритма 'none'. Используйте RS256 или ES256."
                )
            }

            CheckResult(
                checkId = id(),
                status = if (findings.isEmpty()) CheckStatus.OK else CheckStatus.DETECTED,
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )

        } catch (e: Exception) {
            createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}
