package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordBlacklistCheck : SecurityCheck {

    override fun id() = "6.1.2"
    override fun title() = "Контекстные слова в паролях"
    override fun description() = "Проверка использования blacklist для запрета контекстных слов в паролях"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val policy = context.adminService.getRealm().passwordPolicy ?: ""

        val blacklistPatterns = listOf(
            "passwordBlacklist\\(",
            "passwordBlackList\\(",
            "passwordBlacklistRegex\\(",
            "passwordBlacklistFile\\("
        )

        val blacklistEnabled = blacklistPatterns.any { pattern ->
            Regex(pattern).containsMatchIn(policy)
        }

        return if (!blacklistEnabled) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Черный список паролей не настроен",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("passwordPolicy", policy.takeIf { it.isNotBlank() } ?: "Не настроена")),
                        recommendation = "Настройте passwordBlacklist политику для запрета контекстных слов (пароли компании, имена и т.д.)"
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