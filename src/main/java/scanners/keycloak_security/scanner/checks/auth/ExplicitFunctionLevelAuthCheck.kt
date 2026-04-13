package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult
import scanners.keycloak_security.scanner.SecurityCheckHelper.buildCheckResult

/**
 * ASVS V8.2.1: "Verify that the application ensures that function-level access
 * is restricted to consumers with explicit permissions."
 *
 * В Keycloak: проверяем, что default realm roles не дают избыточных привилегий,
 * и что у клиентов определены роли для function-level access control.
 */
@Component
class ExplicitFunctionLevelAuthCheck : SecurityCheck {
    override fun id() = "8.2.1"
    override fun title() = "Явная авторизация на уровне функций"
    override fun description() = "Проверка, что доступ к функциям требует явной авторизации через роли и политики (ASVS V8.2.1)"
    override fun severity() = Severity.HIGH

    companion object {
        val SYSTEM_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
        val PRIVILEGED_ROLE_KEYWORDS = setOf(
            "admin", "manage", "create", "delete", "impersonation",
            "realm-admin", "manage-users", "manage-clients", "manage-realm"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val clients = context.adminService.getClients()

            // 1. Проверяем default realm roles — не содержат ли привилегированные роли
            checkDefaultRoles(context, findings)

            // 2. Проверяем service-account клиенты без client roles
            clients.forEach { client ->
                if (client.clientId in SYSTEM_CLIENTS) return@forEach
                if (client.clientId?.endsWith("-realm") == true) return@forEach

                if (client.isServiceAccountsEnabled == true) {
                    val clientResource = try {
                        context.adminService.getClientResourceById(client.id)
                    } catch (_: Exception) { null }

                    val clientRoles = try {
                        clientResource?.roles()?.list() ?: emptyList()
                    } catch (_: Exception) {
                        emptyList<org.keycloak.representations.idm.RoleRepresentation>()
                    }

                    if (clientRoles.isEmpty()) {
                        findings += Finding(
                            id = id(),
                            title = "Service account '${client.clientId}' без client roles",
                            description = "Клиент '${client.clientId}' имеет service account, но не определяет " +
                                    "собственных client roles. Без ролей невозможно реализовать function-level " +
                                    "access control — все service account запросы имеют одинаковые привилегии.",
                            severity = Severity.MEDIUM,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            clientId = client.clientId,
                            evidence = listOf(
                                Evidence("clientId", client.clientId),
                                Evidence("serviceAccountsEnabled", true),
                                Evidence("clientRolesCount", 0)
                            ),
                            recommendation = "Создайте client roles для разграничения доступа к функциям API"
                        )
                    }
                }
            }

        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }

        return buildCheckResult(id(), title(), findings, start, context.realmName)
    }

    private fun checkDefaultRoles(context: CheckContext, findings: MutableList<Finding>) {
        try {
            val realmRoles = context.adminService.getRealmRoles()
            val defaultRoleName = "default-roles-${context.realmName}"
            val defaultRole = realmRoles.find { it.name == defaultRoleName } ?: return

            val composites = context.adminService.getDefaultRoleComposites(defaultRole.id)

            val privilegedDefaults = composites.filter { role ->
                PRIVILEGED_ROLE_KEYWORDS.any { keyword ->
                    role.name?.contains(keyword, ignoreCase = true) == true
                }
            }

            if (privilegedDefaults.isNotEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Default roles содержат привилегированные роли",
                    description = "Каждый новый пользователь автоматически получает роли: " +
                            "${privilegedDefaults.joinToString { it.name ?: "?" }}. " +
                            "Это нарушает принцип least privilege — доступ к функциям должен назначаться явно.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("defaultRole", defaultRoleName),
                        Evidence("privilegedRoles", privilegedDefaults.joinToString { it.name ?: "?" }),
                        Evidence("totalComposites", composites.size)
                    ),
                    recommendation = "Удалите привилегированные роли из default-roles. Назначайте их явно через группы или админ-интерфейс."
                )
            }
        } catch (_: Exception) {
            // Не удалось получить default roles — пропускаем
        }
    }
}
