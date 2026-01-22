package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class IdpRpSessionConsistencyCheck : SecurityCheck {
    override fun id() = "7.6.1"
    override fun title() = "Согласованность сессий между IdP и Relying Parties"
    override fun description() = "Проверка согласованности настроек времени жизни сессий между Identity Provider и клиентами"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val realm = context.adminService.getRealm()
            val overrides = context.adminService.getClientSessionOverrides()
            val findings = mutableListOf<Finding>()

            val realmIdle = realm.ssoSessionIdleTimeout ?: 0
            val realmMax = realm.ssoSessionMaxLifespan ?: 0

            // 1. Проверка, что в Realm заданы настройки
            if (realmIdle <= 0 || realmMax <= 0) {
                findings.add(Finding(
                    id = id(),
                    title = "Не заданы глобальные настройки сессий",
                    description = "SSO Session Idle или Max не установлены в Realm",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("ssoSessionIdleTimeout", "$realmIdle сек"),
                        Evidence("ssoSessionMaxLifespan", "$realmMax сек")
                    ),
                    recommendation = "Задайте SSO Session Idle и Max в настройках Realm как базовые значения"
                ))
            }

            // 2. Проверка client overrides
            overrides.forEach { (clientId, override) ->
                val (clientIdle, clientMax) = override

                // Проверяем, не превышают ли client overrides значения Realm
                if (clientIdle != null && clientIdle > realmIdle && realmIdle > 0) {
                    findings.add(Finding(
                        id = id(),
                        title = "Клиент превышает SSO Session Idle",
                        description = "Клиент '$clientId' устанавливает client.session.idle.timeout=$clientIdle, что больше значения Realm ($realmIdle)",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("clientIdle", "$clientIdle сек"),
                            Evidence("realmIdle", "$realmIdle сек"),
                            Evidence("difference", "${clientIdle - realmIdle} сек")
                        ),
                        recommendation = "Согласуйте client.session.idle.timeout с SSO Session Idle Realm или обоснуйте необходимость увеличения"
                    ))
                }

                if (clientMax != null && clientMax > realmMax && realmMax > 0) {
                    findings.add(Finding(
                        id = id(),
                        title = "Клиент превышает SSO Session Max",
                        description = "Клиент '$clientId' устанавливает client.session.max.lifespan=$clientMax, что больше значения Realm ($realmMax)",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("clientMax", "$clientMax сек"),
                            Evidence("realmMax", "$realmMax сек"),
                            Evidence("difference", "${clientMax - realmMax} сек")
                        ),
                        recommendation = "Согласуйте client.session.max.lifespan с SSO Session Max Realm"
                    ))
                }

                // Проверяем внутреннюю согласованность client overrides
                if (clientIdle != null && clientMax != null && clientIdle >= clientMax) {
                    findings.add(Finding(
                        id = id(),
                        title = "Некорректные настройки клиента",
                        description = "У клиента '$clientId' client.session.idle.timeout ($clientIdle) ≥ client.session.max.lifespan ($clientMax)",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("clientIdle", "$clientIdle сек"),
                            Evidence("clientMax", "$clientMax сек")
                        ),
                        recommendation = "Исправьте настройки: client.session.idle.timeout должен быть меньше client.session.max.lifespan"
                    ))
                }
            }

            // 3. Статистика по overrides
            if (overrides.isNotEmpty()) {
                findings.add(Finding(
                    id = id(),
                    title = "Статистика client overrides",
                    description = "${overrides.size} клиент(ов) переопределяют настройки сессий",
                    severity = Severity.INFO,
                    status = CheckStatus.OK,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("clientsWithOverrides", overrides.size.toString()),
                        Evidence("exampleOverrides", overrides.keys.take(3).joinToString())
                    ),
                    recommendation = "Регулярно проверяйте обоснованность client overrides для поддержания согласованной политики сессий"
                ))
            }

            return if (findings.any { it.severity >= Severity.MEDIUM }) {
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
                    findings = findings.filter { it.severity == Severity.INFO },
                    durationMs = System.currentTimeMillis() - start
                )
            }

        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}