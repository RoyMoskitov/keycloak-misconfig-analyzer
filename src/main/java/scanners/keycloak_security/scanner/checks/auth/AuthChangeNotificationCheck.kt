package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V6.3.7: "Verify that users are notified after updates to authentication details,
 * such as credential resets or modification of the username or email address."
 *
 * В Keycloak: проверяем что настроен email event listener и включены
 * события изменения credentials для уведомления пользователей.
 */
@Component
class AuthChangeNotificationCheck : SecurityCheck {

    override fun id() = "6.3.7"
    override fun title() = "Уведомления об изменениях аутентификации"
    override fun description() =
        "Проверка, что пользователи уведомляются при изменении credentials (ASVS V6.3.7)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()

            // 1. Проверяем что events включены
            val eventsEnabled = realm.isEventsEnabled == true
            val eventListeners = realm.eventsListeners ?: emptyList()

            if (!eventsEnabled) {
                findings += Finding(
                    id = id(),
                    title = "Login Events отключены",
                    description = "Без включённых событий аутентификации невозможно отслеживать " +
                            "изменения credentials и уведомлять пользователей.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("eventsEnabled", false)),
                    recommendation = "Включите Login Events в Realm Settings → Events"
                )
            }

            // 2. Проверяем наличие email event listener
            val hasEmailListener = eventListeners.any {
                it.contains("email", ignoreCase = true)
            }

            if (!hasEmailListener) {
                findings += Finding(
                    id = id(),
                    title = "Email event listener не настроен",
                    description = "Realm не имеет email event listener в списке event listeners: " +
                            "${eventListeners.ifEmpty { listOf("нет") }.joinToString()}. " +
                            "Без email listener пользователи не получат уведомления при смене пароля, " +
                            "добавлении/удалении MFA или изменении email.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("eventListeners", eventListeners.joinToString()),
                        Evidence("hasEmailListener", false)
                    ),
                    recommendation = "Добавьте 'email' в Event Listeners (Realm Settings → Events → Event Listeners)"
                )
            }

            // 3. Проверяем что SMTP настроен (иначе email уведомления не будут работать)
            val smtpServer = realm.smtpServer
            val smtpConfigured = smtpServer != null &&
                    !smtpServer["host"].isNullOrBlank()

            if (!smtpConfigured) {
                findings += Finding(
                    id = id(),
                    title = "SMTP сервер не настроен",
                    description = "Без настроенного SMTP сервера Keycloak не может отправлять email " +
                            "уведомления пользователям при изменении их credentials.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("smtpConfigured", false)),
                    recommendation = "Настройте SMTP сервер в Realm Settings → Email"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
