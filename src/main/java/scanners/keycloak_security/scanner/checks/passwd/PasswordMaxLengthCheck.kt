package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class PasswordMaxLengthCheck : SecurityCheck {

    override fun id() = "6.2.9"
    override fun title() = "Максимальная длина пароля"
    override fun description() = "Проверка максимальной длины пароля (если указана меньше 64 символов)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val policy = context.adminService.getRealm().passwordPolicy

        val maxLength = policy
            ?.let { Regex("maxLength\\((\\d+)\\)").find(it) }
            ?.groupValues?.get(1)?.toInt()

        return if (maxLength != null && maxLength < 64) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Максимальная длина пароля ограничена значением $maxLength",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("maxLength", maxLength)),
                        recommendation = "Разрешите пароли длиной не менее 64 символов"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
