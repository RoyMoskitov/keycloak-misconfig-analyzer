package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.HttpURLConnection
import java.net.URL

@Component
class HstsHeaderCheck : SecurityCheck {

    override fun id() = "3.4.1"
    override fun title() = "Проверка наличия HSTS заголовка"
    override fun description() =
        "Проверка Strict-Transport-Security заголовка с max-age ≥ 1 год (ASVS V3.4.1)"
    override fun severity() = Severity.HIGH

    companion object {
        // ASVS V3.4.1: "maximum age of at least 1 year must be defined"
        const val MIN_MAX_AGE_SECONDS = 31536000L // 1 год
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val baseUrl = context.adminService.props.serverUrl
        val url = "$baseUrl/realms/${context.realmName}/.well-known/openid-configuration"

        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = false

            val header = conn.getHeaderField("Strict-Transport-Security")

            if (header.isNullOrEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "HSTS заголовок отсутствует",
                    description = "Keycloak не возвращает Strict-Transport-Security. " +
                            "Без HSTS браузер может обращаться к серверу по HTTP, " +
                            "что позволяет SSL stripping атаки.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("Strict-Transport-Security", "отсутствует")),
                    recommendation = "Настройте HSTS через reverse proxy или Keycloak конфигурацию"
                )
            } else {
                // Проверяем max-age
                val maxAgeMatch = Regex("max-age=(\\d+)").find(header)
                val maxAge = maxAgeMatch?.groupValues?.get(1)?.toLongOrNull() ?: 0

                if (maxAge < MIN_MAX_AGE_SECONDS) {
                    findings += Finding(
                        id = id(),
                        title = "HSTS max-age слишком мал",
                        description = "Strict-Transport-Security max-age=$maxAge секунд " +
                                "(${maxAge / 86400} дней). ASVS требует минимум 1 год ($MIN_MAX_AGE_SECONDS секунд).",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("Strict-Transport-Security", header),
                            Evidence("maxAge", maxAge),
                            Evidence("requiredMinimum", MIN_MAX_AGE_SECONDS)
                        ),
                        recommendation = "Увеличьте max-age до $MIN_MAX_AGE_SECONDS (1 год)"
                    )
                }

                // Проверяем includeSubDomains
                if (!header.contains("includeSubDomains", ignoreCase = true)) {
                    findings += Finding(
                        id = id(),
                        title = "HSTS не включает субдомены",
                        description = "Strict-Transport-Security не содержит директиву includeSubDomains. " +
                                "ASVS L2+ требует применение HSTS ко всем субдоменам.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("Strict-Transport-Security", header)),
                        recommendation = "Добавьте includeSubDomains в заголовок HSTS"
                    )
                }
            }
        } catch (_: Exception) {
            // Ошибка подключения
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
