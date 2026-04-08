package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V6.3.5: "Verify that users are notified of suspicious authentication attempts."
 * ASVS V6.3.7: "Verify that users are notified after updates to authentication details."
 *
 * В Keycloak уведомления реализуются через Events. Без включённых Login Events
 * невозможно обнаружить подозрительные попытки входа или отслеживать изменения credentials.
 */
@Component
class LoginEventsEnabledCheck : SecurityCheck {

    override fun id() = "6.3.5"
    override fun title() = "Аудит событий аутентификации"
    override fun description() =
        "Проверка, что события входа и изменения credentials записываются для обнаружения подозрительной активности (ASVS V6.3.5, V6.3.7)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()

            // Проверяем включены ли Login Events
            val eventsEnabled = realm.isEventsEnabled ?: false
            if (!eventsEnabled) {
                findings += Finding(
                    id = id(),
                    title = "Login Events отключены",
                    description = "Запись событий аутентификации отключена. " +
                            "Без Login Events невозможно обнаружить brute force атаки, " +
                            "подозрительные входы из необычных локаций, " +
                            "или отслеживать неудачные попытки аутентификации.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("eventsEnabled", false)),
                    recommendation = "Включите Login Events в Realm Settings → Events → Login Events Settings"
                )
            }

            // Проверяем включены ли Admin Events (для отслеживания изменений credentials)
            val adminEventsEnabled = realm.isAdminEventsEnabled ?: false
            if (!adminEventsEnabled) {
                findings += Finding(
                    id = id(),
                    title = "Admin Events отключены",
                    description = "Запись административных событий отключена. " +
                            "Без Admin Events невозможно отслеживать изменения " +
                            "паролей, MFA, ролей и других критических настроек.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("adminEventsEnabled", false)),
                    recommendation = "Включите Admin Events в Realm Settings → Events → Admin Events Settings"
                )
            }

            // Проверяем срок хранения событий
            if (eventsEnabled) {
                val eventsExpiration = realm.eventsExpiration ?: 0L
                if (eventsExpiration <= 0) {
                    findings += Finding(
                        id = id(),
                        title = "Бессрочное хранение событий не настроено",
                        description = "Events Expiration не задан. События могут удаляться " +
                                "без ограничений, что затрудняет расследование инцидентов.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("eventsExpiration", eventsExpiration)),
                        recommendation = "Настройте срок хранения событий (рекомендуется минимум 90 дней)"
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
