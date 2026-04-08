package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class GrantTypesRestrictionCheck : SecurityCheck {

    override fun id() = "10.4.4"
    override fun title() = "Restrict OAuth grant types per client"
    override fun description() = "Проверка, что клиенты используют только необходимые grant types (ASVS V10.4.4)"
    override fun severity() = Severity.HIGH

    companion object {
        // admin-cli использует Direct Access Grants по дизайну
        val CLIENTS_ALLOWED_DIRECT_ACCESS = setOf("admin-cli")
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        context.adminService.getClients().forEach { client ->
            if (client.clientId in INTERNAL_CLIENTS) return@forEach

            // Implicit Flow — устаревший и небезопасный
            if (client.isImplicitFlowEnabled == true) {
                findings += Finding(
                    id = id(),
                    title = "Implicit Flow включён",
                    description = "Client '${client.clientId}' использует Implicit Flow. " +
                            "Токены передаются через URL fragment, доступны в browser history и HTTP logs.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(Evidence("implicitFlowEnabled", true)),
                    recommendation = "Отключите Implicit Flow и используйте Authorization Code Flow с PKCE"
                )
            }

            // Direct Access Grants (Resource Owner Password Credentials) — передаёт пароль клиенту
            if (client.isDirectAccessGrantsEnabled == true && client.clientId !in CLIENTS_ALLOWED_DIRECT_ACCESS) {
                findings += Finding(
                    id = id(),
                    title = "Direct Access Grants (Password Grant) включён",
                    description = "Client '${client.clientId}' использует Password Grant. " +
                            "Пользователь вводит пароль непосредственно в приложение-клиент, " +
                            "что нарушает принцип делегированной аутентификации.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(Evidence("directAccessGrantsEnabled", true)),
                    recommendation = "Отключите Direct Access Grants и используйте Authorization Code Flow"
                )
            }

            // Клиент с Service Account и Standard Flow одновременно — избыточные grant types
            if (client.isServiceAccountsEnabled == true && client.isStandardFlowEnabled == true
                && client.isPublicClient != true) {
                findings += Finding(
                    id = id(),
                    title = "Избыточные grant types",
                    description = "Client '${client.clientId}' одновременно использует Service Account " +
                            "(Client Credentials) и Standard Flow (Authorization Code). " +
                            "Каждый клиент должен использовать минимально необходимый набор grant types.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(
                        Evidence("serviceAccountsEnabled", true),
                        Evidence("standardFlowEnabled", true)
                    ),
                    recommendation = "Разделите функциональность на два клиента или отключите ненужный grant type"
                )
            }
        }

        // Проверяем accessTokenLifespanForImplicitFlow на realm уровне
        // Если implicit flow включён хоть у одного клиента, этот lifespan важен
        val hasImplicitClients = context.adminService.getClients().any {
            it.clientId !in INTERNAL_CLIENTS && it.isImplicitFlowEnabled == true
        }
        if (hasImplicitClients) {
            val realm = context.adminService.getRealm()
            val implicitLifespan = realm.accessTokenLifespanForImplicitFlow ?: 900
            if (implicitLifespan > 600) {
                findings += Finding(
                    id = id(),
                    title = "Долгоживущие токены для Implicit Flow",
                    description = "accessTokenLifespanForImplicitFlow=$implicitLifespan секунд " +
                            "(${implicitLifespan / 60} минут). Implicit flow передаёт токены через URL fragment — " +
                            "долгоживущие токены увеличивают окно для перехвата через browser history.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("accessTokenLifespanForImplicitFlow", implicitLifespan),
                        Evidence("recommendedMax", 600)
                    ),
                    recommendation = "Сократите accessTokenLifespanForImplicitFlow до ≤ 600 секунд, " +
                            "а лучше отключите Implicit Flow полностью"
                )
            }
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
