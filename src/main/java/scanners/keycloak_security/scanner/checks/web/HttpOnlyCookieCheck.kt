package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import java.net.HttpURLConnection
import java.net.URL

@Component
class HttpOnlyCookieCheck : SecurityCheck {

    override fun id() = "3.3.4"
    override fun title() = "Сессионные cookies имеют HttpOnly"
    override fun description() =
        "Проверяем, что сессионные cookies Keycloak (KEYCLOAK_SESSION, AUTH_SESSION_ID) имеют флаг HttpOnly"

    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/auth?client_id=account&response_type=code"

        val findings = mutableListOf<Finding>()

        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false
            conn.connect()

            val cookies = conn.headerFields["Set-Cookie"] ?: emptyList()

            val sessionCookies = listOf("KEYCLOAK_SESSION", "AUTH_SESSION_ID", "KC_RESTART")
            sessionCookies.forEach { cookieName ->
                cookies.filter { it.startsWith("$cookieName=") }.forEach { cookie ->
                    if (!cookie.contains("HttpOnly", ignoreCase = true)) {
                        findings.add(
                            Finding(
                                id = id(),
                                title = "Сессионная cookie без HttpOnly: $cookieName",
                                description = "Cookie $cookieName должна быть недоступна для JS (HttpOnly)",
                                severity = severity(),
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(Evidence("Set-Cookie", cookie)),
                                recommendation = "Включите флаг HttpOnly для всех сессионных cookie Keycloak"
                            )
                        )
                    }
                }
            }

        } catch (ex: Exception) {
            return CheckResult(
                checkId = id(),
                status = CheckStatus.ERROR,
                findings = emptyList(),
                durationMs = System.currentTimeMillis() - start,
                error = ex.message
            )
        }

        return if (findings.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}
