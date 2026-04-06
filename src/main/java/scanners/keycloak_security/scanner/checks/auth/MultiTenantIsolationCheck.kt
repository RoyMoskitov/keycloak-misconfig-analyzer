package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V8.4.1: "Verify that multi-tenant applications use cross-tenant controls to ensure
 * consumer operations will never affect tenants with which they do not have permissions to interact."
 *
 * В контексте Keycloak: realm — единица изоляции тенанта. Проверяем, что клиенты
 * и настройки realm обеспечивают изоляцию между организациями.
 */
@Component
class MultiTenantIsolationCheck : SecurityCheck {

    override fun id() = "8.4.1"
    override fun title() = "Мультитенантная изоляция"
    override fun description() =
        "Проверка cross-tenant изоляции для мультитенантных сценариев Keycloak (ASVS V8.4.1)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()
            val clients = context.adminService.getClients()
            val idps = context.adminService.getIdentityProviders()

            // 1. Проверяем, что realm-level isolation настроена корректно.
            //    В Keycloak каждый realm — отдельный тенант. Но внутри realm
            //    могут быть клиенты от разных организаций, что нарушает изоляцию.

            // Проверяем наличие клиентов с разными origin (разные организации в одном realm)
            val clientOrigins = clients
                .filter { it.rootUrl != null && it.rootUrl.isNotBlank() }
                .mapNotNull { client ->
                    try {
                        val url = java.net.URI(client.rootUrl)
                        url.host to client.clientId
                    } catch (_: Exception) {
                        null
                    }
                }
                .groupBy({ it.first }, { it.second })

            val multiOriginDomains = clientOrigins.filter { it.value.size > 1 }
            // Это не обязательно проблема, но если доменов слишком много — стоит проверить
            val uniqueDomains = clientOrigins.keys.size
            if (uniqueDomains > 5) {
                findings += Finding(
                    id = id(),
                    title = "Много разных доменов в одном Realm",
                    description = "В realm '${context.realmName}' обнаружены клиенты с $uniqueDomains " +
                            "различными доменами. Если они принадлежат разным организациям, " +
                            "рекомендуется использовать отдельные realm для каждого тенанта.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("uniqueDomains", uniqueDomains),
                        Evidence("domains", clientOrigins.keys.take(10).joinToString())
                    ),
                    recommendation = "Для мультитенантных сценариев используйте отдельный realm " +
                            "для каждой организации, чтобы обеспечить полную изоляцию данных."
                )
            }

            // 2. Проверяем user federation — если настроены разные LDAP/AD источники,
            //    это может указывать на мультитенантность внутри одного realm
            val userFederationProviders = realm.userFederationProviders ?: emptyList()
            if (userFederationProviders.size > 1) {
                findings += Finding(
                    id = id(),
                    title = "Несколько User Federation провайдеров в одном Realm",
                    description = "Настроено ${userFederationProviders.size} User Federation провайдеров. " +
                            "Пользователи из разных источников (LDAP/AD) находятся в одном realm, " +
                            "что может нарушить тенантную изоляцию.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("federationProviders", userFederationProviders.size)
                    ),
                    recommendation = "Разделите User Federation провайдеры по отдельным realm " +
                            "для обеспечения cross-tenant изоляции."
                )
            }

            // 3. Проверяем Identity Providers — несколько корпоративных IdP в одном realm
            //    может означать мультитенантность
            val corporateIdps = idps.filter { idp ->
                idp.providerId in listOf("saml", "oidc", "keycloak-oidc")
            }
            if (corporateIdps.size > 2) {
                findings += Finding(
                    id = id(),
                    title = "Много корпоративных IdP в одном Realm",
                    description = "${corporateIdps.size} корпоративных Identity Providers " +
                            "(SAML/OIDC) настроены в одном realm. Если они представляют разные " +
                            "организации, пользователи из разных тенантов делят общее пространство.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("corporateIdPs", corporateIdps.joinToString { it.alias ?: "?" }),
                        Evidence("count", corporateIdps.size)
                    ),
                    recommendation = "Рассмотрите выделение отдельных realm для каждого корпоративного тенанта."
                )
            }

            // 4. Проверяем, что клиенты не имеют доступа к ролям других клиентов
            //    (cross-client role leakage = потенциальная cross-tenant проблема)
            clients.forEach { client ->
                if (client.isFullScopeAllowed == true &&
                    client.clientId !in setOf("admin-cli", "realm-management", "security-admin-console")) {
                    findings += Finding(
                        id = id(),
                        title = "Full Scope Allowed для '${client.clientId}'",
                        description = "Клиент '${client.clientId}' имеет fullScopeAllowed=true. " +
                                "Это означает, что access token будет содержать ВСЕ роли пользователя " +
                                "из всех клиентов, включая роли, не предназначенные для этого клиента.",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("fullScopeAllowed", true)
                        ),
                        recommendation = "Отключите Full Scope Allowed и назначьте только необходимые " +
                                "client scopes для ограничения видимости ролей."
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
