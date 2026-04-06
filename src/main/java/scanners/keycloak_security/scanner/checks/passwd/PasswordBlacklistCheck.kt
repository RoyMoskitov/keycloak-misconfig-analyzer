package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class PasswordBlacklistCheck : SecurityCheck {

    override fun id() = "6.1.2"
    override fun title() = "Контекстные слова в паролях"
    override fun description() = "Проверка использования blacklist для запрета контекстных и утёкших паролей (ASVS V6.1.2, V6.2.4)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val policy = context.adminService.getRealm().passwordPolicy ?: ""

        // В Keycloak единственная реальная политика blacklist — "passwordBlacklist"
        // Она ссылается на файл со списком запрещённых паролей
        val blacklistEnabled = Regex("passwordBlacklist\\(").containsMatchIn(policy)

        if (!blacklistEnabled) {
            findings += Finding(
                id = id(),
                title = title(),
                description = "Чёрный список паролей не настроен. " +
                        "Без blacklist пользователи могут использовать пароли из утечек, " +
                        "имена организации, имена продуктов и другие легко угадываемые пароли.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("passwordPolicy", policy.ifBlank { "не настроена" }),
                    Evidence("passwordBlacklist", false)
                ),
                recommendation = "Настройте passwordBlacklist в Password Policy. " +
                        "Укажите файл со списком запрещённых паролей, включая: " +
                        "пароли из известных утечек (Have I Been Pwned top-1000), " +
                        "названия организации, продуктов и контекстные слова."
            )
        }

        // Дополнительно: проверяем, не используются ли вместо blacklist менее эффективные
        // правила типа "не содержит username" — это полезно, но не заменяет полноценный blacklist
        val hasNotUsername = policy.contains("notUsername")
        val hasNotEmail = policy.contains("notEmail")

        if (blacklistEnabled && !hasNotUsername) {
            findings += Finding(
                id = id(),
                title = "Не запрещено использование username в пароле",
                description = "Политика blacklist включена, но нет правила 'notUsername'. " +
                        "Пользователь может использовать свой логин как часть пароля.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("notUsername", false),
                    Evidence("passwordPolicy", policy)
                ),
                recommendation = "Добавьте правило 'notUsername' в Password Policy"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
