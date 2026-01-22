package scanners.keycloak_security.usecase.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import java.net.HttpURLConnection
import java.net.URL

@Component
class ReferrerPolicyCheck : SecurityCheck {

    override fun id() = "3.4.5"
    override fun title() = "Проверка Referrer-Policy"
    override fun description() =
        "Проверка того, что Keycloak возвращает заголовок Referrer-Policy для предотвращения утечки данных"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/auth"

        val headerValue = try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false
            conn.connect()
            conn.getHeaderField("Referrer-Policy")
        } catch (ex: Exception) {
            null
        }

        val insecure = headerValue.isNullOrEmpty()
        return if (insecure) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Referrer-Policy заголовок отсутствует",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("Referrer-Policy", headerValue)),
                        recommendation = "Добавьте Referrer-Policy через keycloak.conf или кастомную тему"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(checkId = id(), status = CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}