package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

/**
 * ASVS V13.4.4: "Verify that using the HTTP TRACE method is not supported
 * in production environments, to avoid potential information leakage."
 *
 * TRACE отражает полный запрос обратно клиенту, включая заголовки (cookies, auth).
 * В сочетании с XSS это позволяет Cross-Site Tracing (XST) атаку.
 */
@Component
class HttpTraceDisabledCheck : SecurityCheck {

    override fun id() = "13.4.4"
    override fun title() = "HTTP TRACE отключён"
    override fun description() =
        "Проверка, что метод HTTP TRACE отключён для предотвращения утечки данных (ASVS V13.4.4)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/.well-known/openid-configuration"

        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "TRACE"
            conn.instanceFollowRedirects = false
            conn.connect()

            val status = conn.responseCode
            val contentType = conn.contentType ?: ""

            // TRACE should return 405 Method Not Allowed
            if (status == 200 || contentType.contains("message/http")) {
                findings += Finding(
                    id = id(),
                    title = "HTTP TRACE включён",
                    description = "Сервер отвечает на TRACE запросы (HTTP $status). " +
                            "TRACE отражает все заголовки запроса обратно, включая cookies и " +
                            "Authorization. В сочетании с XSS это позволяет Cross-Site Tracing (XST) атаку.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("httpStatus", status),
                        Evidence("contentType", contentType)
                    ),
                    recommendation = "Отключите метод TRACE в конфигурации Keycloak или reverse proxy"
                )
            }
        } catch (_: Exception) {
            // Ошибка подключения
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
