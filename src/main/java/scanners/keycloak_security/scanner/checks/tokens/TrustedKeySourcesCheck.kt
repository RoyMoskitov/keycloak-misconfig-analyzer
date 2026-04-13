package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult
import scanners.keycloak_security.scanner.SecurityCheckHelper.buildCheckResult

/**
 * ASVS V9.1.3: "Verify that key material used to validate self-contained tokens is from
 * trusted pre-configured sources for the token issuer, preventing attackers from specifying
 * untrusted sources and keys. For JWTs, headers such as 'jku', 'x5u', and 'jwk' must be
 * validated against an allowlist of trusted sources."
 *
 * В Keycloak: проверяем что JWKS URLs клиентов (для private_key_jwt auth) используют HTTPS,
 * и что realm ключи подписи корректно настроены.
 */
@Component
class TrustedKeySourcesCheck : SecurityCheck {
    override fun id() = "9.1.3"
    override fun title() = "Доверенные источники ключей"
    override fun description() = "Проверка, что ключевой материал для валидации токенов из доверенных источников (ASVS V9.1.3)"
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
            // 1. Проверяем realm ключи — наличие активного ключа подписи
            val publicKey = context.adminService.getRealmPublicKey()
            if (publicKey.isNullOrEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Realm не имеет активного ключа подписи",
                    description = "В Realm '${context.realmName}' не найден активный ключ подписи (SIG).",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("activeSigningKey", "not found")),
                    recommendation = "Настройте ключи подписи токенов в Realm → Keys"
                )
            }

            // 2. Проверяем JWKS URL клиентов с private_key_jwt
            val clients = context.adminService.getClients()
            clients.forEach { client ->
                if (client.clientId in INTERNAL_CLIENTS) return@forEach
                if (client.clientId?.endsWith("-realm") == true) return@forEach

                val attrs = client.attributes ?: emptyMap()
                val useJwksUrl = attrs["use.jwks.url"]?.toBoolean() ?: false
                val jwksUrl = attrs["jwks.url"] ?: ""

                if (useJwksUrl && jwksUrl.isNotBlank()) {
                    // JWKS URL настроен — проверяем что он HTTPS
                    if (jwksUrl.startsWith("http://")) {
                        findings += Finding(
                            id = id(),
                            title = "JWKS URL клиента '${client.clientId}' использует HTTP",
                            description = "Клиент '${client.clientId}' загружает ключи с $jwksUrl (без TLS). " +
                                    "Атакующий может подменить ключи через MITM и аутентифицироваться от имени клиента.",
                            severity = Severity.HIGH,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            clientId = client.clientId,
                            evidence = listOf(
                                Evidence("clientId", client.clientId),
                                Evidence("jwks.url", jwksUrl),
                                Evidence("use.jwks.url", true)
                            ),
                            recommendation = "Используйте HTTPS URL для JWKS endpoint клиента"
                        )
                    }
                }

                // 3. Проверяем наличие подозрительных атрибутов с внешними URL ключей
                val externalKeyAttrs = attrs.filter { (key, value) ->
                    (key.contains("jku", ignoreCase = true) ||
                            key.contains("x5u", ignoreCase = true)) &&
                            value.startsWith("http")
                }
                if (externalKeyAttrs.isNotEmpty()) {
                    findings += Finding(
                        id = id(),
                        title = "Клиент '${client.clientId}' ссылается на внешние источники ключей",
                        description = "Атрибуты клиента содержат ссылки на внешние URL ключей: " +
                                externalKeyAttrs.entries.joinToString { "${it.key}=${it.value}" },
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("externalKeyUrls", externalKeyAttrs.entries.joinToString { "${it.key}=${it.value}" })
                        ),
                        recommendation = "Удалите внешние ссылки на ключи. Используйте встроенный JWKS endpoint Keycloak."
                    )
                }
            }

        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }

        return buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
