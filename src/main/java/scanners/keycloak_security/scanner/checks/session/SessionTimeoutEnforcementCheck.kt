package scanners.keycloak_security.scanner.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class SessionTimeoutEnforcementCheck : SecurityCheck {

    override fun id() = "7.3.1"
    override fun title() = "Таймауты сессий (idle и absolute)"
    override fun description() = "Проверка настройки таймаута неактивности и абсолютного лимита жизни сессий (ASVS V7.3.1, V7.3.2)"
    override fun severity() = Severity.HIGH

    companion object {
        const val MAX_SSO_IDLE_SECONDS = 1800        // 30 минут
        const val MAX_SSO_MAX_SECONDS = 86400         // 24 часа
        const val MAX_CLIENT_IDLE_SECONDS = 1800      // 30 минут
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val realm = context.adminService.getRealm()

        val ssoIdle = realm.ssoSessionIdleTimeout ?: 0
        val ssoMax = realm.ssoSessionMaxLifespan ?: 0
        val clientIdle = realm.clientSessionIdleTimeout ?: 0
        val clientMax = realm.clientSessionMaxLifespan ?: 0

        // V7.3.1: Таймаут неактивности
        if (ssoIdle <= 0) {
            findings += Finding(
                id = "7.3.1",
                title = "Таймаут неактивности сессии не задан",
                description = "SSO Session Idle не установлен или равен 0. " +
                        "Сессии не будут истекать при бездействии пользователя, " +
                        "что создаёт риск при оставленных без присмотра устройствах.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("ssoSessionIdleTimeout", ssoIdle)),
                recommendation = "Установите SSO Session Idle ≤ $MAX_SSO_IDLE_SECONDS секунд (${MAX_SSO_IDLE_SECONDS / 60} минут)"
            )
        } else if (ssoIdle > MAX_SSO_IDLE_SECONDS) {
            findings += Finding(
                id = "7.3.1",
                title = "Слишком долгий таймаут неактивности",
                description = "SSO Session Idle = $ssoIdle секунд (${ssoIdle / 60} минут), " +
                        "рекомендуемый максимум — ${MAX_SSO_IDLE_SECONDS / 60} минут.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("ssoSessionIdleTimeout", ssoIdle),
                    Evidence("recommendedMax", MAX_SSO_IDLE_SECONDS)
                ),
                recommendation = "Уменьшите SSO Session Idle до ${MAX_SSO_IDLE_SECONDS / 60} минут"
            )
        }

        // V7.3.2: Абсолютное время жизни сессии
        if (ssoMax <= 0) {
            findings += Finding(
                id = "7.3.2",
                title = "Абсолютное время жизни сессии не задано",
                description = "SSO Session Max не установлен или равен 0. " +
                        "Сессии могут существовать неограниченно долго при активном использовании.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("ssoSessionMaxLifespan", ssoMax)),
                recommendation = "Установите SSO Session Max (например, 28800 секунд / 8 часов)"
            )
        } else if (ssoMax > MAX_SSO_MAX_SECONDS) {
            findings += Finding(
                id = "7.3.2",
                title = "Слишком долгое абсолютное время жизни сессии",
                description = "SSO Session Max = $ssoMax секунд (${ssoMax / 3600} часов), " +
                        "рекомендуемый максимум — ${MAX_SSO_MAX_SECONDS / 3600} часов.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("ssoSessionMaxLifespan", ssoMax),
                    Evidence("recommendedMax", MAX_SSO_MAX_SECONDS)
                ),
                recommendation = "Уменьшите SSO Session Max до ${MAX_SSO_MAX_SECONDS / 3600} часов"
            )
        }

        // Согласованность Idle и Max
        if (ssoIdle > 0 && ssoMax > 0 && ssoIdle >= ssoMax) {
            findings += Finding(
                id = id(),
                title = "SSO Session Idle ≥ SSO Session Max",
                description = "Idle ($ssoIdle сек) >= Max ($ssoMax сек). " +
                        "Таймаут неактивности должен быть значительно меньше абсолютного лимита.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("ssoSessionIdleTimeout", ssoIdle),
                    Evidence("ssoSessionMaxLifespan", ssoMax)
                ),
                recommendation = "Установите Idle значительно меньше Max (например, Idle=30 мин, Max=8 часов)"
            )
        }

        // Проверка client-level overrides
        if (clientIdle > 0 && ssoIdle > 0 && clientIdle > ssoIdle) {
            findings += Finding(
                id = id(),
                title = "Client Session Idle превышает SSO Session Idle",
                description = "Client Session Idle ($clientIdle сек) > SSO Session Idle ($ssoIdle сек). " +
                        "Сессия будет завершена по SSO таймауту, клиентская настройка неэффективна.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("clientSessionIdleTimeout", clientIdle),
                    Evidence("ssoSessionIdleTimeout", ssoIdle)
                ),
                recommendation = "Client Session Idle должен быть ≤ SSO Session Idle"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
