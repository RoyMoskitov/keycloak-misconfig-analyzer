package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class PasswordRotationCheck : SecurityCheck {

    override fun id() = "6.2.10"
    override fun title() = "Принудительная ротация паролей"
    override fun description() = "Проверка, что принудительная ротация паролей не используется без причины (ASVS V6.2.10)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val policy = context.adminService.getRealm().passwordPolicy ?: ""

        // Keycloak поддерживает forceExpiredPasswordChange(days) для принудительной ротации
        val forceExpireMatch = Regex("forceExpiredPasswordChange\\((\\d+)\\)").find(policy)
        val expirationDays = forceExpireMatch?.groupValues?.get(1)?.toInt()

        if (expirationDays != null) {
            // NIST SP 800-63B и ASVS V6.2.10 не рекомендуют принудительную ротацию,
            // так как это приводит к более слабым паролям (password1, password2...)
            val severity = if (expirationDays < 90) Severity.MEDIUM else Severity.LOW

            findings += Finding(
                id = id(),
                title = title(),
                description = "Настроена принудительная ротация паролей каждые $expirationDays дней. " +
                        "NIST SP 800-63B рекомендует НЕ требовать периодическую смену пароля, " +
                        "так как это приводит к использованию предсказуемых паттернов " +
                        "(password1 → password2). Ротация оправдана только при подтверждённой компрометации.",
                severity = severity,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("forceExpiredPasswordChange", expirationDays),
                    Evidence("passwordPolicy", policy)
                ),
                recommendation = "Удалите forceExpiredPasswordChange из Password Policy. " +
                        "Вместо этого используйте мониторинг утечек (Have I Been Pwned) " +
                        "и принудительную смену только при подозрении на компрометацию."
            )
        }

        // Проверяем также passwordHistory — ограничение на повторное использование паролей
        // Это само по себе не плохо, но в сочетании с ротацией бесполезно
        val historyMatch = Regex("passwordHistory\\((\\d+)\\)").find(policy)
        val historySize = historyMatch?.groupValues?.get(1)?.toInt()

        if (historySize != null && expirationDays != null) {
            findings += Finding(
                id = id(),
                title = "История паролей в сочетании с ротацией",
                description = "passwordHistory($historySize) используется вместе с ротацией каждые $expirationDays дней. " +
                        "Это вынуждает пользователей придумывать всё новые пароли, что ведёт к записыванию паролей " +
                        "или использованию тривиальных модификаций.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("passwordHistory", historySize),
                    Evidence("forceExpiredPasswordChange", expirationDays)
                ),
                recommendation = "Если вы удалите ротацию, password history можно оставить " +
                        "для защиты от повторного использования пароля после компрометации."
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
