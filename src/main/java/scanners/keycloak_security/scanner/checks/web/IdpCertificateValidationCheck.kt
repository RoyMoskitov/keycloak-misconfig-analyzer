package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V12.3.2: "Verify that TLS clients validate certificates received
 * before communicating with a TLS server."
 *
 * В контексте Keycloak: проверяем что Identity Providers настроены
 * на валидацию сертификатов/подписей при обмене данными с внешними IdP.
 */
@Component
class IdpCertificateValidationCheck : SecurityCheck {

    override fun id() = "12.3.2"
    override fun title() = "Валидация сертификатов при обмене с IdP"
    override fun description() =
        "Проверка, что Keycloak валидирует подписи и сертификаты от внешних Identity Providers (ASVS V12.3.2)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val idps = context.adminService.getIdentityProviders()

            if (idps.isEmpty()) {
                return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
            }

            idps.forEach { idp ->
                val alias = idp.alias ?: return@forEach
                val config = idp.config ?: emptyMap()
                val providerId = idp.providerId ?: ""

                // Для OIDC IdP: проверяем validateSignature
                if (providerId in listOf("oidc", "keycloak-oidc")) {
                    val validateSignature = config["validateSignature"]?.toBoolean() ?: false
                    if (!validateSignature) {
                        findings += Finding(
                            id = id(),
                            title = "IdP '$alias' не валидирует подписи токенов",
                            description = "OIDC Identity Provider '$alias' имеет validateSignature=false. " +
                                    "Без валидации подписи атакующий может подделать ID Token от этого IdP.",
                            severity = Severity.HIGH,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("idpAlias", alias),
                                Evidence("providerId", providerId),
                                Evidence("validateSignature", false)
                            ),
                            recommendation = "Включите Validate Signatures для IdP '$alias' " +
                                    "и настройте JWKS URL или публичный ключ IdP"
                        )
                    }
                }

                // Для SAML IdP: проверяем wantAssertionsSigned и validateSignature
                if (providerId == "saml") {
                    val wantSigned = config["wantAssertionsSigned"]?.toBoolean() ?: false
                    val validateSig = config["validateSignature"]?.toBoolean() ?: false

                    if (!wantSigned && !validateSig) {
                        findings += Finding(
                            id = id(),
                            title = "SAML IdP '$alias' не требует подписанных assertions",
                            description = "SAML Identity Provider '$alias' не валидирует подписи assertions. " +
                                    "Атакующий может подделать SAML assertion для аутентификации.",
                            severity = Severity.HIGH,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("idpAlias", alias),
                                Evidence("wantAssertionsSigned", wantSigned),
                                Evidence("validateSignature", validateSig)
                            ),
                            recommendation = "Включите 'Want Assertions Signed' и 'Validate Signature' для SAML IdP '$alias'"
                        )
                    }
                }

                // Общее: проверяем URL IdP на HTTP (без TLS)
                val authUrl = config["authorizationUrl"] ?: config["singleSignOnServiceUrl"] ?: ""
                if (authUrl.startsWith("http://") && !authUrl.contains("localhost")) {
                    findings += Finding(
                        id = id(),
                        title = "IdP '$alias' использует HTTP без TLS",
                        description = "Identity Provider '$alias' настроен на HTTP URL: $authUrl. " +
                                "Обмен данными с IdP без TLS позволяет перехват токенов.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("idpAlias", alias),
                            Evidence("url", authUrl)
                        ),
                        recommendation = "Используйте HTTPS для всех URL Identity Provider"
                    )
                }
            }

            // Проверяем User Federation (LDAP) на использование ldap:// без TLS
            val realm = context.adminService.getRealm()
            realm.userFederationProviders?.forEach { provider ->
                val connUrl = provider.config?.get("connectionUrl") ?: ""
                if (connUrl.startsWith("ldap://") && !connUrl.contains("localhost")) {
                    findings += Finding(
                        id = id(),
                        title = "LDAP соединение без TLS",
                        description = "User Federation '${provider.displayName ?: provider.providerName}' " +
                                "использует ldap:// ($connUrl). Учётные данные пользователей " +
                                "передаются в открытом виде при аутентификации через LDAP.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("provider", provider.displayName ?: provider.providerName),
                            Evidence("connectionUrl", connUrl)
                        ),
                        recommendation = "Используйте ldaps:// или настройте StartTLS для LDAP соединения"
                    )
                }
            }

            // Проверяем backchannel logout URLs клиентов на HTTP
            context.adminService.getClients().forEach { client ->
                val backchannelUrl = client.attributes?.get("backchannel.logout.url") ?: ""
                if (backchannelUrl.startsWith("http://") && !backchannelUrl.contains("localhost")) {
                    findings += Finding(
                        id = id(),
                        title = "Backchannel logout по HTTP для '${client.clientId}'",
                        description = "Клиент '${client.clientId}' имеет backchannel logout URL по HTTP: " +
                                "$backchannelUrl. Session info при logout передаётся в открытом виде.",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("backchannelLogoutUrl", backchannelUrl)
                        ),
                        recommendation = "Используйте HTTPS для backchannel logout URL"
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
