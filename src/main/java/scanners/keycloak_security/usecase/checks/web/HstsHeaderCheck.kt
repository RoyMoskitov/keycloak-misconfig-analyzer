package scanners.keycloak_security.usecase.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import java.net.HttpURLConnection
import java.net.URL

@Component
class HstsHeaderCheck : SecurityCheck {

    override fun id() = "3.4.1"
    override fun title() = "Проверка наличия HSTS заголовка"
    override fun description() =
        "Проверка того, что Keycloak возвращает Strict-Transport-Security заголовок (HSTS)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/.well-known/openid-configuration"

        val hstsPresent = try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false

            val header = conn.getHeaderField("Strict-Transport-Security")
            !header.isNullOrEmpty()
        } catch (ex: Exception) {
            false
        }

        return if (!hstsPresent) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "HSTS заголовок отсутствует в ответах Keycloak",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = emptyList(),
                        recommendation = "Настройте HSTS через keycloak.conf или обратный прокси"
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
}