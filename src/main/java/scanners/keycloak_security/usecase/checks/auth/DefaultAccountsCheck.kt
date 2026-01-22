package scanners.keycloak_security.usecase.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class DefaultAccountsCheck : SecurityCheck {

    override fun id() = "6.3.2"
    override fun title() = "Настройки стандартных учётных записей"
    override fun description() = "Проверка на отсутствие небезопасных стандартных аккаунтов, временных паролей и требований first-login"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        try {
            val users = context.adminService.getUsers()
            val realm = context.adminService.getRealm()

            val findings = mutableListOf<Finding>()

            // 1. Поиск стандартных аккаунтов с предсказуемыми именами
            val defaultUsernames = listOf(
                "admin", "administrator", "root", "test", "demo", "guest",
                "user", "default", "system", "keycloak", "master"
            )

            val defaultAccounts = users.filter { user ->
                val username = user.username?.lowercase() ?: ""
                defaultUsernames.any { default -> username.contains(default) }
            }

            if (defaultAccounts.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "Обнаружены стандартные учётные записи",
                        description = "Найдены учётные записи с предсказуемыми именами",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("defaultAccounts", defaultAccounts.joinToString { it.username ?: "unknown" }),
                            Evidence("totalUsers", users.size.toString())
                        ),
                        recommendation = "Переименуйте или удалите стандартные учётные записи. Используйте сложные имена пользователей."
                    )
                )
            }

            // 2. Проверка наличия временных паролей через required actions
            val usersWithTemporaryPassword = users.filter { user ->
                val requiredActions = user.requiredActions ?: emptyList()
                requiredActions.contains("UPDATE_PASSWORD") || requiredActions.contains("CONFIGURE_TOTP")
            }

            if (usersWithTemporaryPassword.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "Пользователи с временными паролями",
                        description = "Найдены пользователи с установленным временным паролем",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("usersWithTemporaryPassword", usersWithTemporaryPassword.size.toString()),
                            Evidence("exampleUsers", usersWithTemporaryPassword.take(3).joinToString { it.username ?: "unknown" })
                        ),
                        recommendation = "Убедитесь, что временные пароли сбрасываются после первого входа. Регулярно проверяйте наличие застойных временных паролей."
                    )
                )
            }

            // 3. Проверка настройки "требовать смену пароля при первом входе" как политики по умолчанию
            val defaultActions = realm.requiredActions ?: emptyList()
            if (defaultActions.any{ it.name == "UPDATE_PASSWORD" }) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "Требование смены пароля при первом входе установлено по умолчанию",
                        description = "Все новые пользователи обязаны менять пароль при первом входе",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("defaultRequiredActions", defaultActions.toString())
                        ),
                        recommendation = "Убедитесь, что временные пароли генерируются безопасно и пользователи меняют их на сложные постоянные пароли."
                    )
                )
            }

            // 4. Проверка наличия отключенных учётных записей с правами администратора
            val disabledAdminAccounts = users.filter { user ->
                val isAdmin = user.realmRoles?.contains("admin") == true ||
                        user.clientRoles?.values?.flatten()?.contains("admin") == true
                val isEnabled = user.isEnabled != false
                isAdmin && !isEnabled
            }

            if (disabledAdminAccounts.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "Отключенные административные учётные записи",
                        description = "Найдены отключенные учётные записи с правами администратора",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("disabledAdminAccounts", disabledAdminAccounts.size.toString()),
                            Evidence("accounts", disabledAdminAccounts.joinToString { it.username ?: "unknown" })
                        ),
                        recommendation = "Рассмотрите возможность полного удаления неиспользуемых административных учётных записей."
                    )
                )
            }

            // 5. Проверка наличия пользователей без MFA
            val usersWithoutMFA = users.filter { user ->
                // Проверяем, есть ли у пользователя настроенный TOTP
                val hasTotp = user.credentials?.any {
                    it.type == "totp" && !it.isTemporary
                } == true
                !hasTotp
            }.take(10) // Ограничиваем для производительности

            if (usersWithoutMFA.size == users.size) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "MFA не настроена ни у одного пользователя",
                        description = "Многофакторная аутентификация не используется",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("totalUsers", users.size.toString()),
                            Evidence("usersWithoutMFA", "100%")
                        ),
                        recommendation = "Включите и настройте MFA для всех пользователей, особенно для административных учётных записей."
                    )
                )
            }

            return if (findings.isNotEmpty()) {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.DETECTED,
                    findings = findings,
                    durationMs = System.currentTimeMillis() - start
                )
            } else {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.OK,
                    durationMs = System.currentTimeMillis() - start
                )
            }

        } catch (e: Exception) {
            return CheckResult(
                checkId = id(),
                status = CheckStatus.ERROR,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Ошибка при проверке стандартных учётных записей: ${e.message}",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("error", e.message ?: "Unknown error"),
                            Evidence("errorType", e.javaClass.simpleName)
                        ),
                        recommendation = "Проверьте права доступа к API Keycloak"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}