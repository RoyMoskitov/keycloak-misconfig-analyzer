package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

@Component
class CookiesSameSiteCheck : SecurityCheck {

    override fun id() = "3.3.2"
    override fun title() = "Cookies должны иметь правильный SameSite"
    override fun description() =
        "Проверка атрибута SameSite в cookies Keycloak (ASVS V3.3.2)"
    override fun severity() = Severity.HIGH

    companion object {
        val SAFE_VALUES = setOf("Lax", "Strict")
        val SESSION_COOKIES = setOf("KEYCLOAK_SESSION", "AUTH_SESSION_ID", "KC_RESTART", "KEYCLOAK_IDENTITY")
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        // SameSite в Keycloak настраивается на уровне сервера (keycloak.conf),
        // не через Realm API. Проверяем фактические cookies из HTTP-ответа.
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/auth?client_id=account&response_type=code"

        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false
            conn.connect()

            val cookies = conn.headerFields["Set-Cookie"] ?: emptyList()

            if (cookies.isEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Cookies не получены",
                    description = "Не удалось получить cookies от Keycloak для проверки SameSite.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("cookiesReceived", 0)),
                    recommendation = "Проверьте доступность endpoint аутентификации"
                )
            } else {
                cookies.forEach { cookie ->
                    val cookieName = cookie.substringBefore("=")
                    if (SESSION_COOKIES.any { cookie.startsWith("$it=") }) {
                        val sameSiteMatch = Regex("SameSite=(\\w+)", RegexOption.IGNORE_CASE).find(cookie)
                        val sameSiteValue = sameSiteMatch?.groupValues?.get(1)

                        if (sameSiteValue == null) {
                            findings += Finding(
                                id = id(),
                                title = "SameSite не установлен для $cookieName",
                                description = "Cookie '$cookieName' не содержит атрибут SameSite. " +
                                        "Браузеры применяют Lax по умолчанию, но явная установка надёжнее.",
                                severity = Severity.MEDIUM,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(Evidence("cookie", cookieName), Evidence("SameSite", "отсутствует")),
                                recommendation = "Установите SameSite=Lax или Strict для всех сессионных cookies"
                            )
                        } else if (sameSiteValue.equals("None", ignoreCase = true)) {
                            // SameSite=None позволяет cross-site отправку — рискованно для сессионных cookies
                            findings += Finding(
                                id = id(),
                                title = "SameSite=None для $cookieName",
                                description = "Cookie '$cookieName' имеет SameSite=None, что позволяет " +
                                        "отправку cookie при cross-site запросах. Это увеличивает " +
                                        "риск CSRF-атак.",
                                severity = Severity.MEDIUM,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(Evidence("cookie", cookieName), Evidence("SameSite", sameSiteValue)),
                                recommendation = "Используйте SameSite=Lax или Strict, если cross-site SSO не требуется"
                            )
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Ошибка подключения
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
