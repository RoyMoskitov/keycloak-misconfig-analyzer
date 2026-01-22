package scanners.keycloak_security.usecase.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import java.net.HttpURLConnection
import java.net.URL

@Component
class ClickjackingProtectionCheck : SecurityCheck {

    override fun id() = "3.4.6"
    override fun title() = "Защита от Clickjacking"
    override fun description() =
        "Проверка того, что Keycloak использует frame-ancestors или X-Frame-Options для защиты от внедрения страниц"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/auth"

        val frameHeader = try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false
            conn.connect()
            conn.getHeaderField("X-Frame-Options") ?: conn.getHeaderField("Content-Security-Policy")
        } catch (ex: Exception) {
            null
        }

        val insecure = frameHeader.isNullOrEmpty()
        return if (insecure) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Защита от clickjacking отсутствует",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("frameProtectionHeader", frameHeader)),
                        recommendation = "Настройте X-Frame-Options или frame-ancestors через keycloak.conf или темы"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(checkId = id(), status = CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}