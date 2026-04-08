package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

/**
 * ASVS V13.4.6: "Verify that the application does not expose detailed
 * version information of backend components."
 *
 * Информация о версии помогает атакующему найти известные CVE.
 */
@Component
class ServerVersionExposureCheck : SecurityCheck {

    override fun id() = "13.4.6"
    override fun title() = "Раскрытие версии сервера"
    override fun description() =
        "Проверка, что Keycloak не раскрывает детальную информацию о версии (ASVS V13.4.6)"
    override fun severity() = Severity.LOW

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val baseUrl = context.adminService.props.serverUrl
        val endpoints = listOf(
            "$baseUrl/realms/${context.realmName}/.well-known/openid-configuration",
            "$baseUrl/realms/${context.realmName}/",
        )

        for (endpoint in endpoints) {
            try {
                val conn = URL(endpoint).openConnection() as HttpURLConnection
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.requestMethod = "GET"
                conn.instanceFollowRedirects = false
                conn.connect()

                // 1. Проверяем Server header
                val serverHeader = conn.getHeaderField("Server")
                if (serverHeader != null && containsVersion(serverHeader)) {
                    findings += Finding(
                        id = id(),
                        title = "Версия сервера в заголовке Server",
                        description = "HTTP заголовок Server содержит информацию о версии: '$serverHeader'. " +
                                "Атакующий может использовать номер версии для поиска известных уязвимостей.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("Server", serverHeader)),
                        recommendation = "Скройте версию сервера через конфигурацию reverse proxy"
                    )
                    break
                }

                // 2. Проверяем X-Powered-By header
                val poweredBy = conn.getHeaderField("X-Powered-By")
                if (poweredBy != null) {
                    findings += Finding(
                        id = id(),
                        title = "Заголовок X-Powered-By раскрывает технологию",
                        description = "HTTP заголовок X-Powered-By: '$poweredBy' раскрывает " +
                                "используемую технологию/фреймворк.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("X-Powered-By", poweredBy)),
                        recommendation = "Удалите заголовок X-Powered-By"
                    )
                    break
                }

            } catch (_: Exception) {
                // Ошибка подключения
            }
        }

        // 3. Проверяем доступность admin console
        try {
            val adminUrl = "$baseUrl/admin/master/console/"
            val conn = URL(adminUrl).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = true
            conn.connect()

            if (conn.responseCode == 200) {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                // Keycloak admin console HTML часто содержит версию
                val versionRegex = Regex("Keycloak[\\s-]*v?([\\d]+\\.[\\d]+\\.[\\d]+)")
                val match = versionRegex.find(body)
                if (match != null) {
                    findings += Finding(
                        id = id(),
                        title = "Версия Keycloak раскрывается через admin console",
                        description = "Admin console содержит информацию о версии: '${match.value}'.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("version", match.groupValues[1]),
                            Evidence("source", "admin console HTML")
                        ),
                        recommendation = "Ограничьте доступ к admin console по IP или через VPN"
                    )
                }
            }
        } catch (_: Exception) {
            // Admin console недоступна — OK
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }

    private fun containsVersion(header: String): Boolean {
        return Regex("\\d+\\.\\d+").containsMatchIn(header)
    }
}
