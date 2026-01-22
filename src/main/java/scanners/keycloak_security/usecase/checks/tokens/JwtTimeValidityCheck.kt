package scanners.keycloak_security.usecase.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.JwtParser
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class JwtTimeValidityCheck : SecurityCheck {

    override fun id() = "9.2.1"
    override fun title() = "Проверка exp / nbf в JWT"
    override fun description() =
        "Проверка наличия и корректности временных ограничений токена"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            val token = context.adminService.getAccessToken().accessToken
            val claims = JwtParser.parse(token)

            val now = System.currentTimeMillis() / 1000
            val exp = (claims["exp"] as? Number)?.toLong()
            val nbf = (claims["nbf"] as? Number)?.toLong()

            if (exp == null) {
                findings += Finding(
                    id(), "Отсутствует exp",
                    "JWT не содержит claim exp",
                    Severity.HIGH, CheckStatus.DETECTED,
                    context.realmName
                )
            } else if (exp < now) {
                findings += Finding(
                    id(), "Токен истёк",
                    "exp меньше текущего времени",
                    Severity.HIGH, CheckStatus.DETECTED,
                    context.realmName,
                    evidence = listOf(
                        Evidence("exp", exp),
                        Evidence("now", now)
                    )
                )
            }

            if (nbf != null && nbf > now) {
                findings += Finding(
                    id(), "Токен ещё не валиден",
                    "nbf больше текущего времени",
                    Severity.HIGH, CheckStatus.DETECTED,
                    context.realmName,
                    evidence = listOf(
                        Evidence("nbf", nbf),
                        Evidence("now", now)
                    )
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
