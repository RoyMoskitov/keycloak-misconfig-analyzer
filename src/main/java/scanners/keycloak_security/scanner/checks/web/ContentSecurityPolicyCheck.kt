package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import java.net.HttpURLConnection
import java.net.URL

@Component
class ContentSecurityPolicyCheck : SecurityCheck {

    override fun id() = "3.4.3"
    override fun title() = "Проверка Content-Security-Policy (CSP)"
    override fun description() =
        "Проверка того, что ответы Keycloak содержат корректный Content-Security-Policy заголовок"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/auth"

        val cspHeader = try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false
            conn.connect()
            conn.getHeaderField("Content-Security-Policy")
        } catch (ex: Exception) {
            null
        }

        val insecure = cspHeader.isNullOrEmpty()

        return if (insecure) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Content-Security-Policy заголовок отсутствует в ответах Keycloak",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("Content-Security-Policy", cspHeader)),
                        recommendation = "Настройте CSP через keycloak.conf или кастомную тему"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(checkId = id(), status = CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}