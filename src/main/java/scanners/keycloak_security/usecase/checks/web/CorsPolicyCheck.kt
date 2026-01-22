package scanners.keycloak_security.usecase.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import java.net.HttpURLConnection
import java.net.URL

@Component
class CorsPolicyCheck : SecurityCheck {

    override fun id() = "3.4.2"
    override fun title() = "Проверка конфигурации CORS"
    override fun description() =
        "Проверка того, что Keycloak возвращает Access-Control-Allow-Origin только для доверенных источников"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        context.adminService.getClientRepresentation()?.webOrigins = mutableListOf(*"+".split(" ").toTypedArray())
        val start = System.currentTimeMillis()
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/userinfo"

        val corsHeader = try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "OPTIONS"
            conn.setRequestProperty("Origin", "https://example.com")
            conn.instanceFollowRedirects = false
            conn.connect()
            conn.getHeaderField("Access-Control-Allow-Origin")
        } catch (ex: Exception) {
            null
        }

        val insecure = corsHeader == "*" || corsHeader.isNullOrEmpty()

        return if (insecure) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "CORS заголовок Access-Control-Allow-Origin отсутствует или разрешает все источники (*)",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("Access-Control-Allow-Origin", corsHeader)),
                        recommendation = "Укажите доверенные источники в Web Origins клиентов Keycloak"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(checkId = id(), status = CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
