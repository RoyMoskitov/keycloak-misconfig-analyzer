package scanners.keycloak_security.scanner.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V7.1.2: "Verify that the documentation defines how many concurrent (parallel)
 * sessions are allowed for one account as well as the intended behaviors and actions
 * to be taken when the maximum number of active sessions is reached."
 *
 * Keycloak не имеет встроенного ограничения на количество параллельных сессий.
 * Без этого ограничения скомпрометированный аккаунт может использоваться
 * одновременно из нескольких мест без обнаружения.
 */
@Component
class ConcurrentSessionsCheck : SecurityCheck {

    override fun id() = "7.1.2"
    override fun title() = "Ограничение параллельных сессий"
    override fun description() =
        "Проверка наличия ограничения на количество одновременных сессий пользователя (ASVS V7.1.2)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()

            // Keycloak не имеет встроенной настройки для ограничения параллельных сессий.
            // Это реализуется через:
            // 1. Custom authenticator (Session Limits authenticator) — SPI
            // 2. Event listeners
            // 3. Custom Authentication Flow с проверкой количества сессий
            //
            // Проверяем наличие косвенных признаков ограничения:

            val allExecutions = context.adminService.getAllAuthenticationExecutions()
            val browserFlowAlias = realm.browserFlow ?: "browser"
            val browserExecutions = allExecutions[browserFlowAlias] ?: emptyList()

            // Ищем session-limits authenticator в browser flow
            val hasSessionLimits = browserExecutions.any { exec ->
                val providerId = exec.providerId ?: ""
                providerId.contains("session-limit", ignoreCase = true) ||
                        providerId.contains("concurrent-session", ignoreCase = true) ||
                        providerId.contains("session-restriction", ignoreCase = true)
            }

            if (!hasSessionLimits) {
                findings += Finding(
                    id = id(),
                    title = "Нет ограничения параллельных сессий",
                    description = "Keycloak не имеет встроенного ограничения на количество " +
                            "одновременных сессий одного пользователя. Один аккаунт может быть " +
                            "использован одновременно из неограниченного числа устройств/браузеров, " +
                            "что затрудняет обнаружение компрометации.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("sessionLimitsAuthenticator", "не найден"),
                        Evidence("browserFlow", browserFlowAlias)
                    ),
                    recommendation = "Рассмотрите использование Session Limits SPI или кастомного " +
                            "authenticator для ограничения параллельных сессий. " +
                            "Альтернатива: мониторинг аномального количества сессий через events."
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
