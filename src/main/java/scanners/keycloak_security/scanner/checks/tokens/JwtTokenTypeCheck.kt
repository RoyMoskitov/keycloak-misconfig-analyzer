package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.service.JwtParser
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.buildCheckResult
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

@Component
class JwtTokenTypeCheck : SecurityCheck {

    override fun id() = "9.2.2"
    override fun title() = "Проверка типа токена (typ)"
    override fun description() =
        "Проверка, что тип токена является ожидаемым и однозначным"
    override fun severity() = Severity.LOW

    private val allowedTypes = setOf(
        "bearer",
        "jwt",
        "at+jwt"
    )

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            val token = context.adminService.getAccessToken().accessToken
            val claims = JwtParser.parse(token)

            val typ = claims["typ"]?.toString()

            if (typ == null) {
                findings += Finding(
                    id(),
                    "Тип токена не указан",
                    "JWT не содержит claim 'typ'. Тип токена определяется неявно.",
                    Severity.INFO,
                    CheckStatus.DETECTED,
                    context.realmName,
                    recommendation =
                        "Рассмотрите возможность явного указания типа токена для упрощения валидации на стороне сервисов."
                )
            } else if (typ.lowercase() !in allowedTypes) {
                findings += Finding(
                    id(),
                    "Неизвестный тип токена",
                    "Обнаружено неожиданное значение typ='$typ'",
                    Severity.MEDIUM,
                    CheckStatus.DETECTED,
                    context.realmName,
                    evidence = listOf(Evidence("typ", typ)),
                    recommendation =
                        "Убедитесь, что все сервисы корректно обрабатывают данный тип токена."
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
