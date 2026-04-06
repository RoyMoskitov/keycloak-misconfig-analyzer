package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

@Component
class ReferrerPolicyCheck : SecurityCheck {

    override fun id() = "3.4.5"
    override fun title() = "Проверка Referrer-Policy"
    override fun description() =
        "Проверка наличия и корректности Referrer-Policy для предотвращения утечки данных (ASVS V3.4.5)"
    override fun severity() = Severity.MEDIUM

    companion object {
        // Безопасные значения, предотвращающие утечку URL параметров
        val SAFE_VALUES = setOf(
            "no-referrer",
            "no-referrer-when-downgrade",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "same-origin"
        )
        // Небезопасные — передают полный URL включая query параметры
        val UNSAFE_VALUES = setOf("unsafe-url")
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/auth"

        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false
            conn.connect()

            val headerValue = conn.getHeaderField("Referrer-Policy")

            if (headerValue.isNullOrEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Referrer-Policy отсутствует",
                    description = "Заголовок Referrer-Policy не установлен. " +
                            "URL авторизации может содержать чувствительные параметры (code, state), " +
                            "которые могут утечь через Referer заголовок.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("Referrer-Policy", "отсутствует")),
                    recommendation = "Установите Referrer-Policy: no-referrer или strict-origin"
                )
            } else if (headerValue.lowercase().trim() in UNSAFE_VALUES) {
                findings += Finding(
                    id = id(),
                    title = "Небезопасное значение Referrer-Policy",
                    description = "Referrer-Policy='$headerValue' передаёт полный URL " +
                            "включая query параметры, что может привести к утечке authorization code и state.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("Referrer-Policy", headerValue)),
                    recommendation = "Замените на no-referrer или strict-origin"
                )
            }
        } catch (_: Exception) {
            // Ошибка подключения
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
