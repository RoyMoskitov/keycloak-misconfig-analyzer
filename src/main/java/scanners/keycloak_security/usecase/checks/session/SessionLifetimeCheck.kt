package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class SessionLifetimeCheck : SecurityCheck {

    override fun id() = "7.1.1"
    override fun title() = "Лимиты времени жизни сессии"
    override fun description() = "Проверка настроек таймаута неактивности и абсолютного лимита жизни сессии"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        // Получаем настройки времени жизни сессий из Realm
        // Значения возвращаются в секундах [citation:5][citation:7]
        val ssoIdle = realm.ssoSessionIdleTimeout ?: 0
        val ssoMax = realm.ssoSessionMaxLifespan ?: 0
        val clientIdle = realm.clientSessionIdleTimeout ?: 0
        val clientMax = realm.clientSessionMaxLifespan ?: 0

        val findings = mutableListOf<Finding>()

        // 1. Проверка SSO Session Idle и Max
        if (ssoIdle <= 0 || ssoMax <= 0) {
            findings.add(createFinding(
                titlePart = "SSO Session",
                idle = ssoIdle,
                max = ssoMax,
                reco = "Установите SSO Session Idle и SSO Session Max в положительные значения (например, 30 мин и 8 часов)."
            ))
        } else if (ssoIdle >= ssoMax) {
            findings.add(createFinding(
                titlePart = "SSO Session",
                idle = ssoIdle,
                max = ssoMax,
                reco = "SSO Session Idle ($ssoIdle сек) должен быть МЕНЬШЕ SSO Session Max ($ssoMax сек)."
            ))
        }

        // 2. Проверка Client Session Idle и Max
        // Если значения для клиента не заданы, Keycloak использует значения SSO [citation:5][citation:6]
        if (clientIdle > 0 || clientMax > 0) {
            if (clientIdle <= 0 || clientMax <= 0) {
                findings.add(createFinding(
                    titlePart = "Client Session",
                    idle = clientIdle,
                    max = clientMax,
                    reco = "Если заданы Client Session Idle или Max, оба параметра должны быть положительными."
                ))
            } else if (clientIdle >= clientMax) {
                findings.add(createFinding(
                    titlePart = "Client Session",
                    idle = clientIdle,
                    max = clientMax,
                    reco = "Client Session Idle ($clientIdle сек) должен быть МЕНЬШЕ Client Session Max ($clientMax сек)."
                ))
            }
            // Дополнительная проверка: Client Idle не должен быть больше SSO Idle (логика Keycloak) [citation:1]
            if (clientIdle > ssoIdle && ssoIdle > 0) {
                findings.add(Finding(
                    id = id(),
                    title = "Client Session Idle превышает SSO Session Idle",
                    description = "Client Session Idle ($clientIdle сек) больше SSO Session Idle ($ssoIdle сек). Сессия клиента будет прервана раньше по SSO таймауту.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("ssoSessionIdleTimeout", "$ssoIdle сек"),
                        Evidence("clientSessionIdleTimeout", "$clientIdle сек")
                    ),
                    recommendation = "Установите Client Session Idle ≤ SSO Session Idle для согласованного поведения."
                ))
            }
        }

        // 3. Проверка на "бесконечные" сессии (значения 0 или -1)
        val unlimitedValues = listOf(ssoIdle, ssoMax, clientIdle, clientMax).filter { it in listOf(0, -1) }
        if (unlimitedValues.isNotEmpty()) {
            findings.add(Finding(
                id = id(),
                title = "Обнаружены настройки бесконечной сессии",
                description = "Значение 0 или -1 для таймаута сессии означает 'никогда не истекает'.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("unlimitedSettings", "SSO Idle: $ssoIdle, SSO Max: $ssoMax, Client Idle: $clientIdle, Client Max: $clientMax")
                ),
                recommendation = "Исключите значения 0 и -1 для всех параметров Idle и Max. Установите разумные лимиты."
            ))
        }

        return buildCheckResult(findings, start, context.realmName)
    }

    private fun createFinding(titlePart: String, idle: Int, max: Int, reco: String): Finding {
        val desc = when {
            idle <= 0 || max <= 0 -> "Параметр $titlePart Idle ($idle сек) или Max ($max сек) не задан или некорректен."
            else -> "$titlePart Idle ($idle сек) должен быть меньше $titlePart Max ($max сек)."
        }
        return Finding(
            id = id(),
            title = "Некорректные настройки $titlePart",
            description = desc,
            severity = Severity.HIGH,
            status = CheckStatus.DETECTED,
            realm = "", // будет установлено в buildCheckResult
            evidence = listOf(
                Evidence("${titlePart.lowercase().replace(" ", "")}Idle", "$idle сек"),
                Evidence("${titlePart.lowercase().replace(" ", "")}Max", "$max сек")
            ),
            recommendation = reco
        )
    }

    private fun buildCheckResult(findings: List<Finding>, start: Long, realmName: String): CheckResult {
        findings.forEach { it.realm = realmName }
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