package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class CookiesSecureCheck : SecurityCheck {

    override fun id() = "3.3.1"
    override fun title() = "Cookies должны иметь атрибут Secure"
    override fun description() =
        "Проверка того, что Keycloak устанавливает cookies с флагом Secure (требует HTTPS)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val requireSsl = realm?.sslRequired?.let { it != "NONE" } ?: false

        return if (!requireSsl) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Realm не требует HTTPS, cookies могут передаваться без Secure",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("sslRequired", realm?.sslRequired)),
                        recommendation = "Включите Require SSL для Realm через админку"
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