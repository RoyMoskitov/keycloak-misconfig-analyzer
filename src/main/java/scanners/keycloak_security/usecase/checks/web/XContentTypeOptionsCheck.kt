package scanners.keycloak_security.usecase.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import java.net.HttpURLConnection
import java.net.URL

@Component
class XContentTypeOptionsCheck : SecurityCheck {

    override fun id() = "3.4.4"
    override fun title() = "Проверка X-Content-Type-Options: nosniff"
    override fun description() =
        "Проверка того, что Keycloak возвращает X-Content-Type-Options: nosniff во всех ответах"
    override fun severity() = Severity.HIGH

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
            conn.getHeaderField("X-Content-Type-Options")
        } catch (ex: Exception) {
            null
        }

        val insecure = headerValue == null || headerValue.lowercase() != "nosniff"

        return if (insecure) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "X-Content-Type-Options отсутствует или некорректен",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("X-Content-Type-Options", headerValue)),
                        recommendation = "Добавьте X-Content-Type-Options: nosniff через keycloak.conf или обратный прокси"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(checkId = id(), status = CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}