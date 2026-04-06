package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class TokenRevocationSupportCheck : SecurityCheck {

    override fun id() = "10.4.9"
    override fun title() = "Поддержка отзыва токенов пользователем"
    override fun description() =
        "Проверка возможности отзыва refresh и access токенов пользователем"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        val realm = context.adminService.getRealm()
        val accountClientEnabled =
            context.adminService.getClients()
                .any { it.clientId == "account" && it.isEnabled == true }

        val issues = mutableListOf<Evidence>()

        if (realm.revokeRefreshToken != true) {
            issues += Evidence("revokeRefreshToken", realm.revokeRefreshToken)
        }

        if (!accountClientEnabled) {
            issues += Evidence("accountClientEnabled", false)
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
                            "Пользователь не может отозвать ранее выданные токены",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = issues,
                        recommendation =
                            "Включите revokeRefreshToken и доступ к управлению сессиями"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
