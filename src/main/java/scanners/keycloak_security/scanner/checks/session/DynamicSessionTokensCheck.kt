package scanners.keycloak_security.scanner.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class DynamicSessionTokensCheck : SecurityCheck {
    override fun id() = "7.2.2"
    override fun title() = "Динамические session tokens"
    override fun description() = "Проверка использования динамических токенов вместо статических ключей (ASVS V7.2.2)"
    override fun severity() = Severity.HIGH

    companion object {
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val clients = context.adminService.getClients()

            clients.forEach { client ->
                val clientId = client.clientId ?: return@forEach
                if (clientId in INTERNAL_CLIENTS) return@forEach

                // ASVS V7.2.2: приложение должно использовать динамически генерируемые токены,
                // а не статические API ключи.
                // В контексте Keycloak: клиенты должны использовать стандартные OAuth2 flow,
                // а не только client credentials с бесконечными токенами.

                val isServiceOnly = client.isServiceAccountsEnabled == true
                        && client.isStandardFlowEnabled != true
                        && client.isDirectAccessGrantsEnabled != true

                if (isServiceOnly) {
                    // Проверяем, не слишком ли долгий access token для service account
                    val tokenLifespan = client.attributes?.get("access.token.lifespan")?.toIntOrNull()
                    if (tokenLifespan != null && tokenLifespan > 3600) {
                        findings += Finding(
                            id = id(),
                            title = "Service account с долгоживущими токенами",
                            description = "Client '$clientId' использует только Service Account " +
                                    "с access token lifespan = $tokenLifespan секунд (${tokenLifespan / 3600} часов). " +
                                    "Долгоживущие токены приближаются к статическим ключам.",
                            severity = Severity.MEDIUM,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            clientId = clientId,
                            evidence = listOf(
                                Evidence("clientId", clientId),
                                Evidence("accessTokenLifespan", tokenLifespan)
                            ),
                            recommendation = "Ограничьте access.token.lifespan до 5-15 минут для service accounts"
                        )
                    }
                }

                // Service account + client-secret = фактически статический API ключ
                if (client.isServiceAccountsEnabled == true) {
                    val authMethod = client.clientAuthenticatorType ?: "client-secret"
                    if (authMethod in listOf("client-secret", "client-secret-post")) {
                        findings += Finding(
                            id = id(),
                            title = "Service account со статическим секретом",
                            description = "Client '$clientId' использует client_credentials grant с методом '$authMethod'. " +
                                    "Статический client_secret фактически является API-ключом — " +
                                    "он не меняется, не истекает и может быть скомпрометирован.",
                            severity = Severity.MEDIUM,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            clientId = clientId,
                            evidence = listOf(
                                Evidence("clientId", clientId),
                                Evidence("clientAuthenticatorType", authMethod),
                                Evidence("serviceAccountsEnabled", true)
                            ),
                            recommendation = "Используйте 'private_key_jwt' или 'client-x509' для динамической аутентификации, " +
                                    "либо внедрите ротацию client_secret"
                        )
                    }
                }

                // Bearer-only — deprecated в KC, модель статического доверия
                if (client.isBearerOnly == true) {
                    findings += Finding(
                        id = id(),
                        title = "Bearer-only клиент (deprecated)",
                        description = "Client '$clientId' использует deprecated режим bearer-only. " +
                                "Bearer-only подразумевает статическую конфигурацию доверия без динамического обмена токенами.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = clientId,
                        evidence = listOf(Evidence("clientId", clientId), Evidence("bearerOnly", true)),
                        recommendation = "Мигрируйте на стандартный confidential клиент с service account"
                    )
                }
            }
        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
