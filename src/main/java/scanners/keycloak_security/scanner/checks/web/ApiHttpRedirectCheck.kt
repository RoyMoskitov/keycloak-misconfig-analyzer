package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/**
 * ASVS V4.1.2: "Verify that only user-facing endpoints automatically redirect
 * from HTTP to HTTPS, while other services or endpoints do not implement
 * transparent redirects."
 *
 * API endpoints (token, userinfo) НЕ должны делать redirect HTTP→HTTPS.
 * Прозрачный redirect маскирует отправку sensitive data по HTTP —
 * клиент не замечает что authorization code/credentials утекли в plaintext.
 */
@Component
class ApiHttpRedirectCheck : SecurityCheck {

    override fun id() = "4.1.2"
    override fun title() = "API endpoints не redirect HTTP→HTTPS"
    override fun description() =
        "Проверка, что API endpoints отклоняют HTTP вместо прозрачного redirect на HTTPS (ASVS V4.1.2)"
    override fun severity() = Severity.MEDIUM

    companion object {
        // API endpoints которые НЕ должны делать redirect (должны отвечать 4xx)
        val API_ENDPOINTS = listOf(
            "/protocol/openid-connect/token" to "Token endpoint",
            "/protocol/openid-connect/userinfo" to "UserInfo endpoint",
            "/protocol/openid-connect/certs" to "JWKS endpoint"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val serverUrl = URI(context.adminService.props.serverUrl)

        // 1. Проверяем OIDC Discovery — все URLs должны быть HTTPS
        checkDiscoveryUrls(context, findings)

        // 2. Если HTTPS — проверяем redirect на API endpoints
        if (serverUrl.scheme == "https") {
            val httpPort = if (serverUrl.port == 443) 80 else serverUrl.port
            val httpBase = "http://${serverUrl.host}:$httpPort"

            API_ENDPOINTS.forEach { (path, label) ->
                val httpUrl = "$httpBase/realms/${context.realmName}$path"
                try {
                    val conn = URL(httpUrl).openConnection() as HttpURLConnection
                    conn.connectTimeout = 5000
                    conn.readTimeout = 5000
                    conn.requestMethod = "POST"
                    conn.instanceFollowRedirects = false
                    conn.connect()

                    val status = conn.responseCode
                    val location = conn.getHeaderField("Location")

                    if (status in listOf(301, 302, 307, 308) && location != null && location.startsWith("https")) {
                        findings += Finding(
                            id = id(),
                            title = "$label делает redirect HTTP→HTTPS",
                            description = "$label отвечает HTTP $status redirect. " +
                                    "API endpoints не должны прозрачно перенаправлять.",
                            severity = Severity.MEDIUM,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("endpoint", path),
                                Evidence("httpStatus", status),
                                Evidence("Location", location)
                            ),
                            recommendation = "Настройте API endpoints отвечать 4xx на HTTP запросы вместо redirect"
                        )
                    }
                } catch (_: Exception) {}
            }
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }

    private fun checkDiscoveryUrls(context: CheckContext, findings: MutableList<Finding>) {
        val baseUrl = context.adminService.props.serverUrl
        val discoveryUrl = "$baseUrl/realms/${context.realmName}/.well-known/openid-configuration"

        try {
            val conn = URL(discoveryUrl).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.connect()

            if (conn.responseCode == 200) {
                val body = conn.inputStream.bufferedReader().readText()
                // Ищем http:// URLs в discovery (должны быть https://)
                val httpUrlPattern = Regex("\"(http://[^\"]+)\"")
                val httpUrls = httpUrlPattern.findAll(body)
                    .map { it.groupValues[1] }
                    .toList()

                if (httpUrls.isNotEmpty()) {
                    findings += Finding(
                        id = id(),
                        title = "OIDC Discovery содержит HTTP URLs",
                        description = "OpenID Configuration содержит ${httpUrls.size} endpoint(s) с http:// вместо https://. " +
                                "Клиенты, использующие discovery, будут обращаться к незащищённым endpoints.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("httpEndpoints", httpUrls.take(5).joinToString("; ")),
                            Evidence("count", httpUrls.size)
                        ),
                        recommendation = "Настройте hostname и proxy-headers в keycloak.conf для корректной генерации HTTPS URLs"
                    )
                }
            }
        } catch (_: Exception) {}
    }
}
