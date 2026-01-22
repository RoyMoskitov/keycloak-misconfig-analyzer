package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class SessionTimeoutEnforcementCheck : SecurityCheck {

    override fun id() = "7.3.1/7.3.2"
    override fun title() = "Принудительное завершение сессии по неактивности и абсолютному времени"
    override fun description() = "Проверка активации таймаута неактивности (Idle) и абсолютного лимита (Max) для сессий"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()
        val ssoIdle = realm.ssoSessionIdleTimeout ?: 0
        val ssoMax = realm.ssoSessionMaxLifespan ?: 0

        val findings = mutableListOf<Finding>()

        // Проверка 7.3.1: Таймаут неактивности (Inactivity timeout)
        if (ssoIdle <= 0) {
            findings.add(Finding(
                id = "7.3.1",
                title = "Таймаут неактивности сессии не задан",
                description = "SSO Session Idle не установлен или равен 0/-1. Сессии не будут истекать из-за неактивности.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("ssoSessionIdleTimeout", "$ssoIdle сек")),
                recommendation = "Установите SSO Session Idle в значение ≤ 1800 сек (30 минут) для принудительного разлогина при неактивности."
            ))
        } else if (ssoIdle > 1800) { // 30 минут = 1800 секунд
            findings.add(Finding(
                id = "7.3.1",
                title = "Слишком долгий таймаут неактивности",
                description = "SSO Session Idle ($ssoIdle сек, ${ssoIdle / 60} мин) превышает рекомендуемые 30 минут.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("ssoSessionIdleTimeout", "$ssoIdle сек")),
                recommendation = "Для повышения безопасности уменьшите SSO Session Idle до 30 минут (1800 секунд) или менее."
            ))
        }

        // Проверка 7.3.2: Абсолютное время жизни (Absolute session lifetime)
        if (ssoMax <= 0) {
            findings.add(Finding(
                id = "7.3.2",
                title = "Абсолютное время жизни сессии не задано",
                description = "SSO Session Max не установлен или равен 0/-1. Сессии могут существовать бесконечно долго.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("ssoSessionMaxLifespan", "$ssoMax сек")),
                recommendation = "Установите SSO Session Max в положительное значение (например, 28800 сек / 8 часов)."
            ))
        } else if (ssoMax > 86400) { // 24 часа = 86400 секунд
            findings.add(Finding(
                id = "7.3.2",
                title = "Слишком долгое абсолютное время жизни сессии",
                description = "SSO Session Max ($ssoMax сек, ${ssoMax / 3600} часов) превышает рекомендуемые 24 часа.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("ssoSessionMaxLifespan", "$ssoMax сек")),
                recommendation = "Рассмотрите уменьшение SSO Session Max до 24 часов (86400 секунд) или менее."
            ))
        }

        // Рекомендация по соотношению Idle и Max (Idle должен быть значительно меньше Max)
        if (ssoIdle > 0 && ssoMax > 0 && ssoIdle > ssoMax / 4) {
            findings.add(Finding(
                id = id(),
                title = "Неоптимальное соотношение Idle и Max",
                description = "SSO Session Idle ($ssoIdle сек) составляет более 25% от SSO Session Max ($ssoMax сек).",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("ssoSessionIdleTimeout", "$ssoIdle сек"),
                    Evidence("ssoSessionMaxLifespan", "$ssoMax сек"),
                    Evidence("idleToMaxRatio", "${(ssoIdle.toDouble() / ssoMax * 100).toInt()}%")
                ),
                recommendation = "Рекомендуется, чтобы Idle был значительно меньше Max (например, Idle=30 мин, Max=8 часов)."
            ))
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
    }
}