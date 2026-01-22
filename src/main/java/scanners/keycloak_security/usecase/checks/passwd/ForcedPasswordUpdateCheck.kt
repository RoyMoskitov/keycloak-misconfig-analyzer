package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class ForcedPasswordUpdateCheck : SecurityCheck {

    override fun id() = "6.2.3"
    override fun title() = "Требование текущего пароля при смене"
    override fun description() = "Проверка настроек обязательной смены пароля без знания текущего"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        try {
            val realm = context.adminService.getRealm()
            val defaultActions = realm.requiredActions ?: emptyList<String>()

            val isDefaultAction = defaultActions.contains("UPDATE_PASSWORD")

            return if (isDefaultAction) {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.DETECTED,
                    findings = listOf(
                        Finding(
                            id = id(),
                            title = title(),
                            description = "UPDATE_PASSWORD установлен как обязательное действие для всех новых пользователей",
                            severity = severity(),
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("isDefaultAction", "true"),
                                Evidence("defaultActions", defaultActions.toString())
                            ),
                            recommendation = "Уберите UPDATE_PASSWORD из default required actions. Смена пароля должна требовать текущий пароль."
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

        } catch (e: Exception) {
            return CheckResult(
                checkId = id(),
                status = CheckStatus.ERROR,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Ошибка при проверке: ${e.message}",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("error", e.message ?: "Unknown error")
                        ),
                        recommendation = "Проверьте подключение к Keycloak"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}