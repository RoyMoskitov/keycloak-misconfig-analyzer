package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

/**
 * ASVS V14.3.2: "Verify that the application sets sufficient anti-caching HTTP response
 * header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers."
 *
 * Без Cache-Control: no-store токены и данные аутентификации могут кешироваться
 * браузерами и прокси-серверами.
 *
 * Каждый endpoint проверяется тем HTTP-методом, который используется в реальных сценариях:
 * - Token endpoint → POST (с credentials)
 * - UserInfo endpoint → GET (с Bearer token)
 * - Authorization endpoint → GET (с query parameters)
 */
@Component
class CacheControlCheck : SecurityCheck {

    override fun id() = "14.3.2"
    override fun title() = "Anti-caching заголовки для чувствительных endpoints"
    override fun description() =
        "Проверка Cache-Control: no-store на endpoint-ах с чувствительными данными (ASVS V14.3.2)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val baseUrl = context.adminService.props.serverUrl
        val realmUrl = "$baseUrl/realms/${context.realmName}"

        // 1. Token endpoint — POST с credentials
        checkTokenEndpoint(realmUrl, context, findings)

        // 2. Authorization endpoint — GET с параметрами
        checkWithGet(
            "$realmUrl/protocol/openid-connect/auth?client_id=account&response_type=code",
            "Authorization endpoint",
            "/protocol/openid-connect/auth",
            Severity.LOW,
            context, findings
        )

        // 3. UserInfo endpoint — GET с Bearer token
        checkUserInfoEndpoint(realmUrl, context, findings)

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }

    private fun checkTokenEndpoint(realmUrl: String, context: CheckContext, findings: MutableList<Finding>) {
        val path = "/protocol/openid-connect/token"
        try {
            val conn = URL("$realmUrl$path").openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

            val props = context.adminService.props
            val body = if (props.grantType == "client_credentials") {
                "grant_type=client_credentials&client_id=${props.clientId}&client_secret=${props.clientSecret}"
            } else {
                "grant_type=password&client_id=${props.clientId}&username=${props.username}&password=${props.password}"
            }
            conn.outputStream.use { it.write(body.toByteArray()) }

            conn.responseCode // trigger response processing
            evaluateHeaders(conn, "Token endpoint", path, Severity.MEDIUM, context, findings)
        } catch (_: Exception) {}
    }

    private fun checkUserInfoEndpoint(realmUrl: String, context: CheckContext, findings: MutableList<Finding>) {
        val path = "/protocol/openid-connect/userinfo"
        try {
            val token = context.adminService.getAccessToken().accessToken

            val conn = URL("$realmUrl$path").openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Authorization", "Bearer $token")

            val status = conn.responseCode

            // UserInfo недоступен для service accounts (client_credentials без openid scope) —
            // это корректное поведение по спецификации OIDC, не проблема безопасности
            if (status == 403 || status == 401) return

            evaluateHeaders(conn, "UserInfo endpoint", path, Severity.LOW, context, findings)
        } catch (_: Exception) {}
    }

    private fun checkWithGet(
        url: String, label: String, path: String, severity: Severity,
        context: CheckContext, findings: MutableList<Finding>
    ) {
        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false

            conn.responseCode // trigger response processing
            evaluateHeaders(conn, label, path, severity, context, findings)
        } catch (_: Exception) {}
    }

    private fun evaluateHeaders(
        conn: HttpURLConnection, label: String, path: String, severity: Severity,
        context: CheckContext, findings: MutableList<Finding>
    ) {
        val cacheControl = conn.getHeaderField("Cache-Control") ?: ""
        val pragma = conn.getHeaderField("Pragma") ?: ""

        val hasNoStore = cacheControl.contains("no-store", ignoreCase = true)

        if (!hasNoStore) {
            findings += Finding(
                id = id(),
                title = "Отсутствует Cache-Control: no-store для $label",
                description = "$label ($path) не возвращает Cache-Control: no-store. " +
                        "Ответы могут кешироваться браузером или прокси, " +
                        "что приведёт к утечке токенов или данных пользователя из кеша.",
                severity = severity,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("endpoint", path),
                    Evidence("Cache-Control", cacheControl.ifEmpty { "отсутствует" }),
                    Evidence("Pragma", pragma.ifEmpty { "отсутствует" })
                ),
                recommendation = "Добавьте заголовок Cache-Control: no-store для $label"
            )
        }
    }
}
