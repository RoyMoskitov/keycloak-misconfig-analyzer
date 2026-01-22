package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordForceExpireCheck : SecurityCheck {

    override fun id() = "KC-PASS-03"
    override fun title() = "Принудительная смена пароля"
    override fun description() = "Проверка наличия принудительной периодической смены пароля"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val policy = context.adminService.getRealm().passwordPolicy

        val forced = policy
            ?.let { Regex("forceExpiredPasswordChange\\((\\d+)\\)").find(it) }
            ?.groupValues?.get(1)?.toInt()

        return if (forced != null) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Найдена принудительная периодическая смена пароля: $forced дней",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("forceExpiredPasswordChange", forced)),
                        recommendation = "Отключите периодическую смену пароля"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
