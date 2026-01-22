package scanners.keycloak_security.usecase.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class CookiesSameSiteCheck : SecurityCheck {

    override fun id() = "3.3.2"
    override fun title() = "Cookies должны иметь правильный SameSite"
    override fun description() =
        "Проверка, что Keycloak устанавливает атрибут SameSite в cookies согласно конфигурации Realm"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        // Пример: извлекаем глобальную настройку SameSite из конфига или Realm (если настроено)
        val sameSite = realm?.attributes?.get("sameSiteCookie") ?: "Lax"

        val allowed = setOf("Lax", "Strict", "None")
        return if (sameSite !in allowed) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Настройка SameSite некорректна или отсутствует",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("sameSiteCookie", sameSite)),
                        recommendation = "Установите SameSite в Lax, Strict или None в настройках Realm или keycloak.conf"
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