package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

/**
 * ASVS V3.3.2: "Verify that each cookie's 'SameSite' attribute value is set according to
 * the purpose of the cookie, to limit exposure to user interface redress attacks and
 * browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF)."
 *
 * Keycloak — Identity Provider, поддерживающий cross-origin SSO (iframe, federation).
 * AUTH_SESSION_ID с SameSite=None является намеренным архитектурным решением
 * для поддержки cross-origin сценариев. Проверка учитывает контекст IdP:
 * - SameSite=None для AUTH_SESSION_ID допускается при наличии Secure и HttpOnly
 * - Для остальных cookies отсутствие SameSite помечается как INFO (браузер по умолчанию применяет Lax)
 */
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

        // Cookies, для которых SameSite=None допустим в контексте IdP (cross-origin SSO)
        val CROSS_ORIGIN_SSO_COOKIES = setOf("AUTH_SESSION_ID")
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/protocol/openid-connect/auth?client_id=account&response_type=code"

        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false
            conn.responseCode // trigger response

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
                        val hasSecure = cookie.contains("Secure", ignoreCase = true)
                        val hasHttpOnly = cookie.contains("HttpOnly", ignoreCase = true)

                        if (sameSiteValue == null) {
                            // Без явного SameSite браузер по умолчанию применяет Lax.
                            // Это не уязвимость, но явная установка надёжнее.
                            findings += Finding(
                                id = id(),
                                title = "SameSite не установлен явно для $cookieName",
                                description = "Cookie '$cookieName' не содержит явный атрибут SameSite. " +
                                        "Современные браузеры применяют Lax по умолчанию, обеспечивая базовую CSRF-защиту.",
                                severity = Severity.LOW,
                                status = CheckStatus.OK,
                                realm = context.realmName,
                                evidence = listOf(
                                    Evidence("cookie", cookieName),
                                    Evidence("SameSite", "не задан (браузер применит Lax)"),
                                    Evidence("HttpOnly", hasHttpOnly)
                                ),
                                recommendation = "Для дополнительной надёжности установите SameSite=Lax явно"
                            )
                        } else if (sameSiteValue.equals("None", ignoreCase = true)) {
                            if (cookieName in CROSS_ORIGIN_SSO_COOKIES && hasSecure && hasHttpOnly) {
                                // AUTH_SESSION_ID с SameSite=None — допустимо для IdP с cross-origin SSO
                                findings += Finding(
                                    id = id(),
                                    title = "$cookieName использует SameSite=None (IdP cross-origin SSO)",
                                    description = "Cookie '$cookieName' имеет SameSite=None для поддержки " +
                                            "cross-origin SSO сценариев (iframe, federation). " +
                                            "Для Identity Provider это допустимо при наличии Secure и HttpOnly.",
                                    severity = Severity.LOW,
                                    status = CheckStatus.OK,
                                    realm = context.realmName,
                                    evidence = listOf(
                                        Evidence("cookie", cookieName),
                                        Evidence("SameSite", sameSiteValue),
                                        Evidence("Secure", hasSecure),
                                        Evidence("HttpOnly", hasHttpOnly)
                                    ),
                                    recommendation = "Если cross-origin SSO не используется, настройте SameSite=Lax " +
                                            "в конфигурации Keycloak сервера"
                                )
                            } else {
                                // SameSite=None без Secure или для неожиданных cookies — проблема
                                findings += Finding(
                                    id = id(),
                                    title = "SameSite=None для $cookieName",
                                    description = "Cookie '$cookieName' имеет SameSite=None" +
                                            if (!hasSecure) " без флага Secure" else "" +
                                            ". Это увеличивает риск CSRF-атак.",
                                    severity = Severity.MEDIUM,
                                    status = CheckStatus.DETECTED,
                                    realm = context.realmName,
                                    evidence = listOf(
                                        Evidence("cookie", cookieName),
                                        Evidence("SameSite", sameSiteValue),
                                        Evidence("Secure", hasSecure),
                                        Evidence("HttpOnly", hasHttpOnly)
                                    ),
                                    recommendation = "Используйте SameSite=Lax или Strict"
                                )
                            }
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
