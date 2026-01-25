package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck


@Component
class ProxyHeadersCheck : SecurityCheck {

    override fun id() = "4.1.3"
    override fun title() = "Проверка доверия к заголовкам прокси (X-Forwarded-*)"
    override fun description() =
        "Проверяем, что Keycloak не позволяет пользователям подменять заголовки прокси " +
                "и корректно настроен proxy mode и proxyAddressForwarding"

    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()
        val findings = mutableListOf<Finding>()

        val proxyMode = realm.attributes?.get("proxyMode") ?: "NONE"
        val proxyForwarding = realm.attributes?.get("proxyAddressForwarding")?.toBoolean() ?: false

        // Если proxy forwarding включен, но mode не EDGE или REVERSE → возможно подмена
        if (proxyForwarding && proxyMode == "NONE") {
            findings.add(
                Finding(
                    id = id(),
                    title = "Опасная конфигурация доверия X-Forwarded-*",
                    description = "Proxy forwarding включен, но proxy mode = NONE. Пользователи могут подменять заголовки X-Forwarded-*",
                    severity = severity(),
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("proxyMode", proxyMode),
                        Evidence("proxyAddressForwarding", proxyForwarding.toString())
                    ),
                    recommendation =
                        "Если сервер не за доверенным прокси, отключите proxyAddressForwarding или установите proxy mode = EDGE/REVERSE"
                )
            )
        }

        return if (findings.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = findings,
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
