package scanners.keycloak_security.scanner.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import org.slf4j.LoggerFactory

@Component
class ReauthenticationForSensitiveActionsCheck : SecurityCheck {
    private val logger = LoggerFactory.getLogger(ReauthenticationForSensitiveActionsCheck::class.java)

    override fun id() = "7.5.1"
    override fun title() = "Повторная аутентификация для критических действий"
    override fun description() = "Проверка, что критические изменения (пароль, email, MFA) требуют повторной аутентификации (ASVS V7.5.1)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            // ASVS V7.5.1: "application requires full re-authentication before allowing
            // modifications to sensitive account attributes such as email, phone, MFA configuration"

            // В Keycloak Account Console по умолчанию требует текущий пароль при смене пароля.
            // Но мы можем проверить:

            // 1. Account Console доступна (без неё нет стандартного UI для reauthentication)
            val accountConsoleAvailable = context.adminService.isAccountConsoleAvailable()
            if (!accountConsoleAvailable) {
                findings += Finding(
                    id = id(),
                    title = "Account Console недоступна",
                    description = "Account Console отключена. Без неё нет стандартного механизма " +
                            "повторной аутентификации при смене критических атрибутов.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("accountConsoleAvailable", false)),
                    recommendation = "Включите Account Console для обеспечения reauthentication при смене настроек"
                )
            }

            // 2. Проверяем наличие потока reset credentials
            val allExecutions = context.adminService.getAllAuthenticationExecutions()
            val realm = context.adminService.getRealm()
            val resetFlowAlias = realm.resetCredentialsFlow ?: "reset credentials"

            if (!allExecutions.containsKey(resetFlowAlias)) {
                findings += Finding(
                    id = id(),
                    title = "Поток сброса учётных данных не найден",
                    description = "Не найден поток '$resetFlowAlias'. " +
                            "Без него невозможно обеспечить безопасный процесс сброса пароля.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("resetCredentialsFlow", resetFlowAlias)),
                    recommendation = "Настройте поток '$resetFlowAlias' для безопасного сброса паролей"
                )
            }

            // 3. Проверяем Required Actions — должны быть доступны для смены пароля и MFA
            val requiredActions = context.adminService.getRequiredActions()
            val criticalActions = mapOf(
                "UPDATE_PASSWORD" to "Смена пароля",
                "CONFIGURE_TOTP" to "Настройка MFA"
            )

            criticalActions.forEach { (alias, label) ->
                val action = requiredActions.find { it.alias.equals(alias, ignoreCase = true) }
                if (action == null || action.isEnabled == false) {
                    findings += Finding(
                        id = id(),
                        title = "Required Action '$label' недоступна",
                        description = "Действие '$alias' отключено или отсутствует. " +
                                "Без него невозможно принудительно запросить $label у пользователя.",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("action", alias),
                            Evidence("available", action != null),
                            Evidence("enabled", action?.isEnabled ?: false)
                        ),
                        recommendation = "Включите Required Action '$alias'"
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
