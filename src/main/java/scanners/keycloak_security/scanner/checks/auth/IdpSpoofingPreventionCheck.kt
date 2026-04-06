package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V6.8.1: "Verify that, if the application supports multiple identity providers (IdPs),
 * the user's identity cannot be spoofed via another supported identity provider
 * (eg. by using the same user identifier). The standard mitigation would be for the application
 * to register and identify the user using a combination of the IdP ID (serving as a namespace)
 * and the user's ID in the IdP."
 */
@Component
class IdpSpoofingPreventionCheck : SecurityCheck {

    override fun id() = "6.8.1"
    override fun title() = "Предотвращение спуфинга между Identity Providers"
    override fun description() =
        "Проверка, что пользователь из одного IdP не может выдать себя за пользователя другого IdP (ASVS V6.8.1)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val idps = context.adminService.getIdentityProviders()

            // Если нет внешних IdP, проверка не применима
            if (idps.isEmpty()) {
                return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
            }

            // 1. Проверяем настройки каждого IdP на предмет spoofing
            idps.forEach { idp ->
                val alias = idp.alias ?: return@forEach
                val config = idp.config ?: emptyMap()

                // Проверяем Trust Email — если включено, email из IdP доверяется без верификации.
                // Атакующий через скомпрометированный IdP может подставить чужой email
                // и получить доступ к аккаунту другого пользователя.
                val trustEmail = config["trustEmail"]?.toBoolean() ?: false
                if (trustEmail) {
                    findings += Finding(
                        id = id(),
                        title = "Trust Email включён для IdP '$alias'",
                        description = "Identity Provider '$alias' имеет trustEmail=true. " +
                                "Email от этого IdP принимается без верификации. " +
                                "Если атакующий контролирует этот IdP, он может подставить " +
                                "произвольный email и получить доступ к аккаунту другого пользователя.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("idpAlias", alias),
                            Evidence("trustEmail", true),
                            Evidence("providerId", idp.providerId ?: "unknown")
                        ),
                        recommendation = "Отключите Trust Email для IdP '$alias', " +
                                "если вы не полностью доверяете этому провайдеру. " +
                                "Включите верификацию email для пользователей, " +
                                "входящих через внешние IdP."
                    )
                }

                // Проверяем First Broker Login Flow — должен содержать шаг верификации
                val firstBrokerLoginFlow = idp.firstBrokerLoginFlowAlias
                if (firstBrokerLoginFlow.isNullOrEmpty()) {
                    findings += Finding(
                        id = id(),
                        title = "Не задан First Broker Login Flow для IdP '$alias'",
                        description = "У IdP '$alias' не настроен поток первого входа. " +
                                "Без First Broker Login Flow Keycloak не сможет корректно " +
                                "связать внешнюю идентичность с локальным аккаунтом.",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("idpAlias", alias),
                            Evidence("firstBrokerLoginFlow", "не задан")
                        ),
                        recommendation = "Настройте First Broker Login Flow с проверкой " +
                                "существующего аккаунта и верификацией email"
                    )
                }
            }

            // 2. Если настроено несколько IdP, проверяем что нет одинаковых IdP
            //    с разными настройками (потенциальный вектор для spoofing)
            if (idps.size > 1) {
                // Проверяем, что все IdP используют уникальные идентификаторы
                // В Keycloak пользователи из IdP идентифицируются как idp_alias + user_id,
                // что по умолчанию соответствует рекомендации ASVS (namespace + id).
                // Но если несколько IdP сопоставляют пользователей по email,
                // может произойти конфликт.

                val idpsWithSyncMode = idps.filter { idp ->
                    val syncMode = idp.config?.get("syncMode")
                    syncMode == "FORCE" || syncMode == "IMPORT"
                }

                val idpsLinkingByEmail = idps.filter { idp ->
                    val trustEmail = idp.config?.get("trustEmail")?.toBoolean() ?: false
                    trustEmail
                }

                if (idpsLinkingByEmail.size > 1) {
                    findings += Finding(
                        id = id(),
                        title = "Несколько IdP с Trust Email",
                        description = "Более одного IdP имеют trustEmail=true: " +
                                "${idpsLinkingByEmail.joinToString { it.alias ?: "?" }}. " +
                                "Пользователь может быть сопоставлен по email из разных IdP, " +
                                "что создаёт вектор для account takeover через менее защищённый IdP.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("totalIdPs", idps.size),
                            Evidence("idpsWithTrustEmail",
                                idpsLinkingByEmail.joinToString { it.alias ?: "?" })
                        ),
                        recommendation = "Оставьте trustEmail=true только для одного " +
                                "наиболее доверенного IdP. Для остальных используйте " +
                                "верификацию email при первом входе."
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
