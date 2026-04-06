package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class ForcedPasswordUpdateCheck : SecurityCheck {

    override fun id() = "6.2.3"
    override fun title() = "Требование текущего пароля при смене"
    override fun description() = "Проверка, что смена пароля требует ввод текущего пароля (ASVS V6.2.3)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()

            // 1. Проверяем, что Account Console включён — через него пользователи меняют пароль,
            //    и стандартная форма Account Console всегда требует текущий пароль
            val accountConsoleAvailable = context.adminService.isAccountConsoleAvailable()

            if (!accountConsoleAvailable) {
                findings += Finding(
                    id = id(),
                    title = "Account Console недоступна",
                    description = "Account Console отключена или недоступна. " +
                            "Без Account Console пользователи не могут самостоятельно менять пароль " +
                            "через стандартный интерфейс, требующий ввод текущего пароля.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("accountConsoleAvailable", false)),
                    recommendation = "Включите клиент 'account-console' для самостоятельной смены пароля пользователями"
                )
            }

            // 2. Проверяем, что Direct Access Grants отключен для account-console
            //    (чтобы нельзя было сменить пароль через API без текущего пароля)
            val accountClients = context.adminService.getClients().filter {
                it.clientId in listOf("account", "account-console")
            }

            accountClients.forEach { client ->
                if (client.isDirectAccessGrantsEnabled == true) {
                    findings += Finding(
                        id = id(),
                        title = "Direct Access Grants включён для '${client.clientId}'",
                        description = "Клиент '${client.clientId}' имеет включённый Direct Access Grants, " +
                                "что может позволить программную смену пароля без верификации текущего.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("directAccessGrantsEnabled", true)
                        ),
                        recommendation = "Отключите Direct Access Grants для клиента '${client.clientId}'"
                    )
                }
            }

            // 3. Проверяем наличие UPDATE_PASSWORD в required actions (должен быть enabled)
            val requiredActions = context.adminService.getRequiredActions()
            val updatePasswordAction = requiredActions.find {
                it.alias.equals("UPDATE_PASSWORD", ignoreCase = true)
            }

            if (updatePasswordAction == null || updatePasswordAction.isEnabled == false) {
                findings += Finding(
                    id = id(),
                    title = "Действие UPDATE_PASSWORD отключено",
                    description = "Required Action 'UPDATE_PASSWORD' отключена или отсутствует. " +
                            "Без неё администраторы не смогут принудительно запросить смену пароля " +
                            "у пользователей при подозрении на компрометацию.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("updatePasswordAction", updatePasswordAction?.alias ?: "NOT FOUND"),
                        Evidence("enabled", updatePasswordAction?.isEnabled ?: false)
                    ),
                    recommendation = "Включите Required Action 'UPDATE_PASSWORD'"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
