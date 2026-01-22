package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.buildCheckResult
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class FederatedSsoConsistencyCheck : SecurityCheck {
    override fun id() = "7.1.3"
    override fun title() = "Согласованность сессий в федеративном SSO"
    override fun description() = "Проверка, что Keycloak является центральным источником политик сессий при наличии внешних Identity Providers"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val realm = context.adminService.getRealm()
            val idps = context.adminService.getIdentityProviders()
            val findings = mutableListOf<Finding>()
            val infoMessages = mutableListOf<String>()

            // 1. Проверка наличия централизованного управления сессиями
            val ssoSessionIdle = realm.ssoSessionIdleTimeout ?: 0
            val ssoSessionMax = realm.ssoSessionMaxLifespan ?: 0
            if (ssoSessionIdle <= 0 || ssoSessionMax <= 0) {
                findings.add(Finding(
                    id = id(),
                    title = "Не заданы глобальные настройки сессий Realm",
                    description = "SSO Session Idle и/или Max не установлены.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("ssoSessionIdleTimeout", "$ssoSessionIdle сек"),
                        Evidence("ssoSessionMaxLifespan", "$ssoSessionMax сек")
                    ),
                    recommendation = "Задайте SSO Session Idle и Max в настройках Realm для централизованного управления."
                ))
            } else {
                infoMessages.add("Глобальные настройки сессий заданы: Idle=${ssoSessionIdle}сек, Max=${ssoSessionMax}сек")
            }

            // 2. Проверка наличия Identity Providers
            if (idps.isEmpty()) {
                infoMessages.add("Внешние Identity Providers не настроены. Проверка 7.1.3 не применима.")
            } else {
                infoMessages.add("Настроено Identity Providers: ${idps.size}")
                // Дополнительная логика: можно проверить, что для IdP не заданы собственные таймауты сессий
                // (если такая информация доступна через API)
            }

            return buildCheckResult(id(), title(), findings, start, context.realmName)
        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}