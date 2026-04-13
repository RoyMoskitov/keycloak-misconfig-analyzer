package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

/**
 * ASVS V13.4.5: "Verify that documentation (such as for internal APIs) and monitoring
 * endpoints are not exposed unless explicitly intended."
 *
 * Проверяем доступность health, metrics и других внутренних endpoints Keycloak.
 */
@Component
class InternalEndpointsExposureCheck : SecurityCheck {

    override fun id() = "13.4.5"
    override fun title() = "Раскрытие внутренних endpoints"
    override fun description() =
        "Проверка, что мониторинг и внутренние endpoints не доступны публично (ASVS V13.4.5)"
    override fun severity() = Severity.MEDIUM

    companion object {
        val INTERNAL_ENDPOINTS = listOf(
            "/health" to "Health endpoint",
            "/health/ready" to "Readiness probe",
            "/health/live" to "Liveness probe",
            "/metrics" to "Metrics endpoint",
            "/realms/master/metrics" to "Realm metrics"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val serverUri = java.net.URI(context.adminService.props.serverUrl)
        val host = serverUri.host

        // KC 25+ serves health/metrics on management port 9000 by default
        // Also check main port in case legacy-observability-interface=true
        val mainPort = if (serverUri.port != -1) serverUri.port else 8080
        val managementPort = 9000
        val portsToCheck = listOf(
            managementPort to "management port ($managementPort)",
            mainPort to "main port ($mainPort)"
        )

        for ((port, portLabel) in portsToCheck) {
            INTERNAL_ENDPOINTS.forEach { (path, label) ->
                try {
                    val url = "http://$host:$port$path"
                    val conn = URL(url).openConnection() as HttpURLConnection
                    conn.connectTimeout = 2000
                    conn.readTimeout = 2000
                    conn.requestMethod = "GET"
                    conn.instanceFollowRedirects = false
                    conn.connect()

                    val status = conn.responseCode
                    if (status == 200) {
                        val contentType = conn.contentType ?: ""
                        findings += Finding(
                            id = id(),
                            title = "$label доступен на $portLabel",
                            description = "$label ($url) отвечает HTTP 200. " +
                                    "Внутренние endpoints раскрывают информацию о состоянии сервера, " +
                                    "метрики, версию и конфигурацию.",
                            severity = if (path.contains("metrics")) Severity.MEDIUM else Severity.LOW,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("endpoint", url),
                                Evidence("httpStatus", status),
                                Evidence("contentType", contentType)
                            ),
                            recommendation = "Ограничьте доступ к $path: не публикуйте management port ($managementPort) наружу"
                        )
                    }
                } catch (_: Exception) {
                    // Endpoint недоступен — OK
                }
            }
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
