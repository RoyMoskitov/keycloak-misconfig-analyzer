package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import java.net.HttpURLConnection
import java.net.URL

@Component
class ContentTypeCheck : SecurityCheck {

    override fun id() = "4.1.1"
    override fun title() = "Проверка корректного Content-Type"
    override fun description() =
        "Проверка того, что Keycloak возвращает корректный Content-Type в HTTP-ответах для HTML, JSON и ресурсов тем"
    override fun severity() = Severity.HIGH

    private val endpoints = listOf(
        "/protocol/openid-connect/auth",
        "/protocol/openid-connect/token",
        "/.well-known/openid-configuration"
    )

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val baseUrl = context.adminService.props.serverUrl
        val findings = mutableListOf<Finding>()

        endpoints.forEach { endpoint ->
            val url = "$baseUrl/realms/${context.realmName}$endpoint"
            try {
                val conn = URL(url).openConnection() as HttpURLConnection
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.requestMethod = "GET"
                conn.instanceFollowRedirects = false
                conn.connect()
                val contentType = conn.contentType

                val expected = when {
                    endpoint.contains("auth") -> "text/html"
                    endpoint.contains("token") || endpoint.contains("openid-configuration") -> "application/json"
                    else -> null
                }

                if (expected != null && (contentType == null || !contentType.startsWith(expected))) {
                    findings.add(
                        Finding(
                            id = id(),
                            title = title(),
                            description = "Неверный Content-Type для $endpoint: $contentType, ожидается $expected",
                            severity = severity(),
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(Evidence("Content-Type", contentType ?: "null")),
                            recommendation = "Проверьте конфигурацию тем или сервера для корректного Content-Type"
                        )
                    )
                }

            } catch (_: Exception) {
                // пропускаем таймауты/ошибки
            }
        }

        return if (findings.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(checkId = id(), status = CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}