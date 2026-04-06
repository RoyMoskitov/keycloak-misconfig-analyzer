package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

@Component
class CorsPolicyCheck : SecurityCheck {

    override fun id() = "3.4.2"
    override fun title() = "Проверка конфигурации CORS"
    override fun description() =
        "Проверка ограничения CORS Access-Control-Allow-Origin доверенными источниками (ASVS V3.4.2)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        // 1. Проверяем Web Origins в конфигурации клиентов (через Admin API, только чтение)
        val clients = context.adminService.getClients()
        clients.forEach { client ->
            val webOrigins = client.webOrigins ?: emptyList()
            if (webOrigins.contains("*")) {
                findings += Finding(
                    id = id(),
                    title = "Wildcard в Web Origins",
                    description = "Client '${client.clientId}' имеет '*' в Web Origins, " +
                            "что разрешает CORS-запросы от любого домена.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(
                        Evidence("clientId", client.clientId),
                        Evidence("webOrigins", webOrigins.joinToString())
                    ),
                    recommendation = "Замените '*' на конкретные доверенные origins в настройках клиента"
                )
            }
        }

        // 2. Проверяем фактический CORS заголовок от Keycloak
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/userinfo"

        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "OPTIONS"
            conn.setRequestProperty("Origin", "https://attacker.example.com")
            conn.instanceFollowRedirects = false
            conn.connect()

            val corsHeader = conn.getHeaderField("Access-Control-Allow-Origin")

            if (corsHeader == "*") {
                findings += Finding(
                    id = id(),
                    title = "CORS разрешает все источники",
                    description = "Keycloak отвечает Access-Control-Allow-Origin: * " +
                            "на запросы от произвольных доменов.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("Access-Control-Allow-Origin", corsHeader)),
                    recommendation = "Настройте конкретные Web Origins для клиентов Keycloak"
                )
            } else if (corsHeader == "https://attacker.example.com") {
                findings += Finding(
                    id = id(),
                    title = "CORS отражает произвольный Origin",
                    description = "Keycloak отражает произвольный Origin в Access-Control-Allow-Origin, " +
                            "что равноценно wildcard '*'.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("Access-Control-Allow-Origin", corsHeader)),
                    recommendation = "Настройте строгий список Web Origins для клиентов"
                )
            }
        } catch (_: Exception) {
            // Ошибка подключения — не можем проверить заголовки
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
