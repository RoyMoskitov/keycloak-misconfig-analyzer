package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

@Component
class HttpsOnlyCheck : SecurityCheck {

    override fun id() = "12.2.1"
    override fun title() = "Использование HTTPS для внешних endpoints"
    override fun description() =
        "Проверка того, что Keycloak не обслуживает чувствительные endpoints по HTTP"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        val baseUrl = URI(context.adminService.props.serverUrl)
        val httpUrl = URI(
            "http",
            baseUrl.userInfo,
            baseUrl.host,
            if (baseUrl.port != -1) baseUrl.port else 80,
            "/realms/${context.realmName}/.well-known/openid-configuration",
            null,
            null
        )

        val result = checkHttp(httpUrl.toString())

        val insecure =
            result.statusCode == 200 ||
                    (result.statusCode in 200..299 && result.bodyContainsData)

        return if (insecure) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Keycloak обслуживает endpoint по HTTP без защиты TLS",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("httpStatus", result.statusCode),
                            Evidence("locationHeader", result.location ?: "none")
                        ),
                        recommendation =
                            "Отключите HTTP или настройте обязательный redirect на HTTPS. " +
                                    "Чувствительные endpoints не должны быть доступны по plaintext HTTP."
                    )
                ),
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

    private fun checkHttp(url: String): HttpResult {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = false
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"

            val status = conn.responseCode
            val location = conn.getHeaderField("Location")

            HttpResult(
                statusCode = status,
                location = location,
                bodyContainsData = status == 200
            )
        } catch (ex: Exception) {
            // connection refused / timeout = OK
            HttpResult(
                statusCode = -1,
                location = null,
                bodyContainsData = false
            )
        }
    }

    private data class HttpResult(
        val statusCode: Int,
        val location: String?,
        val bodyContainsData: Boolean
    )
}
