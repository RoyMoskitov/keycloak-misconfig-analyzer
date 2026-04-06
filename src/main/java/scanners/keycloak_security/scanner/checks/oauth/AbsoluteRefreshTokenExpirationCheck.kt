package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class AbsoluteRefreshTokenExpirationCheck : SecurityCheck {

    override fun id() = "10.4.8"
    override fun title() = "Абсолютный срок жизни Refresh Token"
    override fun description() =
        "Проверка наличия абсолютного срока жизни refresh и offline токенов"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()
        val issues = mutableListOf<Evidence>()


        val ssoSessionMaxLifespan = realm.ssoSessionMaxLifespan
        if (ssoSessionMaxLifespan == null || ssoSessionMaxLifespan <= 0) {
            issues += Evidence("ssoSessionMaxLifespan", ssoSessionMaxLifespan)
        }

        if (realm.offlineSessionMaxLifespanEnabled != true) {
            issues += Evidence(
                "offlineSessionMaxLifespanEnabled",
                realm.offlineSessionMaxLifespanEnabled
            )
        }

        if (realm.offlineSessionMaxLifespan == null || realm.offlineSessionMaxLifespan <= 0) {
            issues += Evidence(
                "offlineSessionMaxLifespan",
                realm.offlineSessionMaxLifespan
            )
        }

        return if (issues.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Refresh / offline tokens не имеют абсолютного срока жизни",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = issues,
                        recommendation =
                            "Задайте ssoSessionMaxLifespan для refresh токенов и " +
                                    "offlineSessionMaxLifespan для offline токенов"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}