package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordHashIterationsCheck : SecurityCheck {

    override fun id() = "KC-PASS-05"
    override fun title() = "Итерации хеширования пароля"
    override fun description() = "Проверка достаточного количества итераций хеширования пароля"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val policy = context.adminService.getRealm().passwordPolicy

        val iterations = policy
            ?.let { Regex("hashIterations\\((\\d+)\\)").find(it) }
            ?.groupValues?.get(1)?.toInt()

        return if (iterations == null || iterations < 20000) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Число итераций хеширования пароля недостаточно: $iterations",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("hashIterations", iterations)),
                        recommendation = "Установите hashIterations не менее 20000"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
