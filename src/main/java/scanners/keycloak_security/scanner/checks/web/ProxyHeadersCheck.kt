package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

@Component
class ProxyHeadersCheck : SecurityCheck {

    override fun id() = "4.1.3"
    override fun title() = "Проверка доверия к заголовкам прокси (X-Forwarded-*)"
    override fun description() =
        "Проверка, что Keycloak не доверяет X-Forwarded-* заголовкам от недоверенных источников (ASVS V4.1.3)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        // В Quarkus Keycloak (17+) proxy настраивается через серверную конфигурацию
        // (--proxy=edge|reforward|passthrough), а не через realm attributes.
        // Через Admin API мы не можем прочитать серверную конфигурацию напрямую.
        //
        // Но можем проверить косвенно: отправить запрос с поддельным X-Forwarded-Host
        // и проверить, принимает ли Keycloak его (отражает в ответах).

        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/.well-known/openid-configuration"

        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.setRequestProperty("X-Forwarded-Host", "attacker.example.com")
            conn.setRequestProperty("X-Forwarded-Proto", "http")
            conn.instanceFollowRedirects = false
            conn.connect()

            val responseCode = conn.responseCode
            if (responseCode == 200) {
                val body = conn.inputStream.bufferedReader().readText()

                // Если Keycloak отражает поддельный X-Forwarded-Host в OIDC discovery
                if (body.contains("attacker.example.com")) {
                    findings += Finding(
                        id = id(),
                        title = "Keycloak доверяет поддельным X-Forwarded-* заголовкам",
                        description = "При отправке X-Forwarded-Host: attacker.example.com " +
                                "Keycloak отразил его в OIDC discovery endpoints. " +
                                "Атакующий может подменить URL авторизации и перенаправить пользователей.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("X-Forwarded-Host", "attacker.example.com"),
                            Evidence("reflected", true)
                        ),
                        recommendation = "Настройте proxy mode в keycloak.conf: " +
                                "--proxy=edge (за reverse proxy) или --proxy=passthrough (прямой доступ). " +
                                "Для Keycloak < 17: установите Proxy Mode в настройках Realm."
                    )
                }
            }
        } catch (_: Exception) {
            // Ошибка подключения
        }

        // Дополнительно: проверяем realm attributes (для старых версий Keycloak < 17)
        val realm = context.adminService.getRealm()
        val proxyMode = realm.attributes?.get("proxyMode")
        val proxyForwarding = realm.attributes?.get("proxyAddressForwarding")?.toBoolean() ?: false

        if (proxyForwarding && (proxyMode == null || proxyMode == "NONE")) {
            findings += Finding(
                id = id(),
                title = "Proxy forwarding включён без proxy mode",
                description = "proxyAddressForwarding=true, но proxyMode=NONE. " +
                        "Keycloak доверяет X-Forwarded-* заголовкам от любых источников.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("proxyMode", proxyMode ?: "NONE"),
                    Evidence("proxyAddressForwarding", true)
                ),
                recommendation = "Установите proxy mode = EDGE или REENCRYPT, либо отключите proxyAddressForwarding"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
