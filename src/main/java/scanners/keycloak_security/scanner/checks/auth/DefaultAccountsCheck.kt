package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class DefaultAccountsCheck : SecurityCheck {

    override fun id() = "6.3.2"
    override fun title() = "Настройки стандартных учётных записей"
    override fun description() = "Проверка отсутствия или отключённости стандартных аккаунтов (ASVS V6.3.2)"
    override fun severity() = Severity.HIGH

    companion object {
        // ASVS: "default user accounts (e.g., 'root', 'admin', or 'sa') are not present or are disabled"
        val DEFAULT_USERNAMES = setOf(
            "admin", "administrator", "root", "sa", "test", "demo",
            "guest", "default", "system", "keycloak"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val users = context.adminService.getUsers()

            // 1. Поиск включённых стандартных аккаунтов с предсказуемыми именами
            //    ASVS допускает их наличие если они disabled
            val enabledDefaultAccounts = users.filter { user ->
                val username = user.username?.lowercase() ?: ""
                user.isEnabled != false && username in DEFAULT_USERNAMES
            }

            if (enabledDefaultAccounts.isNotEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Обнаружены активные стандартные учётные записи",
                    description = "Найдены включённые учётные записи с предсказуемыми именами: " +
                            "${enabledDefaultAccounts.joinToString { it.username ?: "?" }}. " +
                            "ASVS V6.3.2 требует, чтобы такие аккаунты были удалены или отключены.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("enabledDefaultAccounts",
                            enabledDefaultAccounts.joinToString { it.username ?: "?" }),
                        Evidence("totalUsers", users.size)
                    ),
                    recommendation = "Отключите или удалите стандартные учётные записи. " +
                            "Используйте уникальные имена для административных аккаунтов."
                )
            }

            // 2. Проверка пользователей с временными паролями, которые давно не менялись
            val usersWithPendingPasswordChange = users.filter { user ->
                user.isEnabled != false &&
                        user.requiredActions?.contains("UPDATE_PASSWORD") == true
            }

            if (usersWithPendingPasswordChange.isNotEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Пользователи с нерешённым требованием смены пароля",
                    description = "${usersWithPendingPasswordChange.size} пользователей имеют " +
                            "pending UPDATE_PASSWORD. Это может означать, что временные пароли " +
                            "не были сменены на постоянные.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("count", usersWithPendingPasswordChange.size),
                        Evidence("examples",
                            usersWithPendingPasswordChange.take(5).joinToString { it.username ?: "?" })
                    ),
                    recommendation = "Проверьте, что временные пароли имеют ограниченный срок действия " +
                            "и пользователи действительно меняют их при первом входе."
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
