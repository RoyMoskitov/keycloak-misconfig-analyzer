package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class ForcedLogoutProtectionCheck : SecurityCheck {

    override fun id() = "10.6.2"
    override fun title() = "Защита от принудительного logout"
    override fun description() =
        "Проверка, что logout не может быть инициирован без валидации пользователя"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        val riskyClients = context.adminService.getClients()
            .filter { client ->
                client.protocol == "openid-connect" &&
                        client.isFrontchannelLogout == true &&
                        client.attributes?.get("post.logout.redirect.uris") != null
            }

        return if (riskyClients.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = riskyClients.map { client ->
                    Finding(
                        id = id(),
                        title = title(),
                        description =
                            "Возможен logout без явной пользовательской валидации",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("frontchannelLogout", true)
                        ),
                        recommendation =
                            "Используйте RP-Initiated Logout с id_token_hint и избегайте auto-logout"
                    )
                },
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
