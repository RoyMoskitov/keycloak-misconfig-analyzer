package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class ConsentRevocationCheck : SecurityCheck {

    override fun id() = "10.7.3"
    override fun title() = "Отзыв согласий пользователем"
    override fun description() =
        "Проверка возможности просмотра и отзыва ранее выданных согласий"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        val realm = context.adminService.getRealm()
        val accountEnabled = context.adminService.getClients()
            .any { it.clientId == "account" && it.isEnabled == true }

        val issues = mutableListOf<Evidence>()

        if (!accountEnabled) {
            issues += Evidence("accountClientEnabled", false)
        }

        if (realm.revokeRefreshToken != true) {
            issues += Evidence("revokeRefreshToken", realm.revokeRefreshToken)
        }

        return if (issues.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description =
                            "Пользователь не может отозвать ранее выданные согласия",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = issues,
                        recommendation =
                            "Включите account console и revokeRefreshToken"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
