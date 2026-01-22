package scanners.keycloak_security.usecase.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class TrustedKeySourcesCheck : SecurityCheck {
    override fun id() = "9.1.3"
    override fun title() = "Доверенные источники ключей (jku, jwk, x5u)"
    override fun description() = "Проверка использования только внутренних JWKS endpoint и отсутствия внешних key URLs"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()
            val client = context.adminService.getClientRepresentation()

            if (client == null) {
                return CheckResult(
                    checkId = id(),
                    status = CheckStatus.ERROR,
                    findings = listOf(Finding(
                        id = id(),
                        title = "Клиент не найден",
                        description = "Не удалось получить клиент для проверки источников ключей",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = emptyList(),
                        recommendation = "Убедитесь, что clientId в конфигурации указан верно"
                    )),
                    durationMs = System.currentTimeMillis() - start
                )
            }

            val clientId = client.clientId ?: "unknown"

            // 1. Проверка наличия публичного ключа у realm
            val publicKey = context.adminService.getRealmPublicKey()

            if (publicKey.isNullOrEmpty()) {
                findings.add(Finding(
                    id = id(),
                    title = "Realm не имеет публичного ключа",
                    description = "Realm '${context.realmName}' не имеет сконфигурированного публичного ключа для подписи токенов",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("realmName", context.realmName),
                        Evidence("publicKeyConfigured", "false")
                    ),
                    recommendation = "Настройте ключи подписи токенов в разделе Realm → Keys"
                ))
            } else {
                // Проверяем, что ключ не является тестовым или дефолтным
                if (publicKey.contains("-----BEGIN PUBLIC KEY-----") &&
                    publicKey.contains("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA")) {
                    // Это стандартный тестовый ключ Keycloak - небезопасно
                    findings.add(Finding(
                        id = id(),
                        title = "Используется тестовый публичный ключ Keycloak",
                        description = "Realm '${context.realmName}' использует стандартный тестовый ключ Keycloak",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("realmName", context.realmName),
                            Evidence("keyType", "test/default key")
                        ),
                        recommendation = "Сгенерируйте уникальные ключи для продакшн среды"
                    ))
                }
            }

            // 2. Проверка использования внешних ключей через KeysMetadata
            val isUsingExternalKeys = context.adminService.isUsingExternalKeys()

            if (isUsingExternalKeys) {
                findings.add(Finding(
                    id = id(),
                    title = "Realm использует внешние ключи",
                    description = "В конфигурации ключей realm '${context.realmName}' обнаружены ссылки на внешние URL",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("realmName", context.realmName),
                        Evidence("issue", "external key URLs detected")
                    ),
                    recommendation = "Удалите все внешние ссылки на ключи. Используйте только внутренний JWKS endpoint Keycloak"
                ))
            }

            // 3. Проверка атрибутов клиента на наличие внешних key URLs
            val clientAttributes = client.attributes ?: emptyMap()

            // Проверяем потенциально опасные атрибуты
            val externalKeyUrls = clientAttributes.filter { (key, value) ->
                key.contains("jwk", ignoreCase = true) ||
                        key.contains("x5u", ignoreCase = true) ||
                        key.contains("jku", ignoreCase = true) ||
                        (key.contains("key") && value.startsWith("http", ignoreCase = true))
            }

            if (externalKeyUrls.isNotEmpty()) {
                findings.add(Finding(
                    id = id(),
                    title = "Клиент использует внешние источники ключей",
                    description = "Клиент '$clientId' настроен использовать внешние URL для ключей",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("externalKeyConfigs",
                            externalKeyUrls.entries.joinToString { "${it.key}=${it.value}" }
                        )
                    ),
                    recommendation = "Удалите конфигурации внешних ключей. Используйте только внутренний JWKS endpoint Keycloak"
                ))
            }

            // 4. Проверка правильного issuer
            val issuer = realm.attributes?.get("issuer") ?: ""
            val expectedIssuer = "${context.adminService.props.serverUrl}/realms/${context.realmName}"

            if (issuer.isNotEmpty() && issuer != expectedIssuer) {
                findings.add(Finding(
                    id = id(),
                    title = "Нестандартный issuer в конфигурации",
                    description = "Realm имеет нестандартный issuer URL",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("configuredIssuer", issuer),
                        Evidence("expectedIssuer", expectedIssuer)
                    ),
                    recommendation = "Убедитесь, что issuer соответствует стандартному формату Keycloak"
                ))
            }

            // 5. Проверка протокола OpenID Connect Configuration
            // Keycloak автоматически предоставляет .well-known конфигурацию
            // Проверяем, что клиент использует стандартные endpoint'ы

            val usesCustomEndpoints = clientAttributes.any { (key, value) ->
                key.contains("endpoint") &&
                        !value.contains("/realms/${context.realmName}/protocol/openid-connect")
            }

            if (usesCustomEndpoints) {
                findings.add(Finding(
                    id = id(),
                    title = "Клиент использует кастомные OIDC endpoints",
                    description = "Клиент '$clientId' настроен на нестандартные OIDC endpoints",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("clientId", clientId)
                    ),
                    recommendation = "Используйте стандартные endpoints Keycloak для гарантии безопасности"
                ))
            }

            // 6. Проверка использования стандартного JWKS endpoint
            val jwksUriConfigured = clientAttributes.any { (key, value) ->
                key.contains("jwks", ignoreCase = true) ||
                        key.contains("certs", ignoreCase = true)
            }

            if (jwksUriConfigured) {
                // Если клиент явно настраивает JWKS URI, проверяем что это внутренний
                val jwksUri = clientAttributes.entries.firstOrNull {
                    it.key.contains("jwks", ignoreCase = true) ||
                            it.key.contains("certs", ignoreCase = true)
                }?.value ?: ""

                if (!jwksUri.contains("/realms/${context.realmName}/protocol/openid-connect/certs")) {
                    findings.add(Finding(
                        id = id(),
                        title = "Клиент использует нестандартный JWKS endpoint",
                        description = "Клиент '$clientId' настроен на использование кастомного JWKS endpoint",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("jwksUri", jwksUri)
                        ),
                        recommendation = "Используйте стандартный JWKS endpoint Keycloak: /realms/{realm}/protocol/openid-connect/certs"
                    ))
                }
            }

            return createResult(findings, start)

        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }

    private fun createResult(findings: List<Finding>, start: Long): CheckResult {
        return CheckResult(
            checkId = id(),
            status = if (findings.isNotEmpty()) CheckStatus.DETECTED else CheckStatus.OK,
            findings = findings,
            durationMs = System.currentTimeMillis() - start
        )
    }
}