package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.service.JwtParser
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

@Component
class JwtAudienceCheck : SecurityCheck {

    override fun id() = "9.2.3"
    override fun title() = "Проверка назначения токена"
    override fun description() =
        "Проверка aud / azp в JWT"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            val token = context.adminService.getAccessToken().accessToken
            val claims = JwtParser.parse(token)

            val aud = when (val a = claims["aud"]) {
                is String -> listOf(a)
                is Collection<*> -> a.map { it.toString() }
                else -> emptyList()
            }

            val azp = claims["azp"]?.toString()

            if (aud.isEmpty() && azp != context.adminService.props.clientId) {
                findings += Finding(
                    id(), "Назначение токена не подтверждено",
                    "Отсутствует aud, azp не совпадает с clientId",
                    Severity.HIGH, CheckStatus.DETECTED,
                    context.realmName,
                    evidence = listOf(
                        Evidence("azp", azp ?: "null"),
                        Evidence("clientId", context.adminService.props.clientId)
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
