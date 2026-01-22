package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordMinLengthCheck : SecurityCheck {

    override fun id() = "6.2.1"

    override fun title() = "Минимальная длина пароля"

    override fun description() =
        "Проверка минимальной длины пароля в политике Keycloak"

    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()
        val policy = realm.passwordPolicy

        val minLength = policy
            ?.let { Regex("length\\((\\d+)\\)").find(it) }
            ?.groupValues
            ?.get(1)
            ?.toInt()

        return if (minLength == null || minLength < 8) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Минимальная длина пароля менее 8 символов",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("passwordPolicy", policy),
                            Evidence("minLength", minLength)
                        ),
                        recommendation = "Установите минимальную длину пароля не менее 8 символов"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}

