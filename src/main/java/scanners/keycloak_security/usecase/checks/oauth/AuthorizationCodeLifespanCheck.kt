package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class AuthorizationCodeLifespanCheck : SecurityCheck {

    override fun id() = "10.4.3"
    override fun title() = "Authorization code lifespan"
    override fun description() = "Проверка времени жизни authorization code (≤ 10 минут)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val lifespan = realm.accessCodeLifespanLogin

        return if (lifespan != null && lifespan > 600) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Authorization code lifespan слишком большой: $lifespan секунд",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("accessCodeLifespanLogin", lifespan)),
                        recommendation = "Установите Access Code Lifespan ≤ 600 секунд (10 минут)"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
