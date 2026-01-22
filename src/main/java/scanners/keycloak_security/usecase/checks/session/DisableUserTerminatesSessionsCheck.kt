package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class DisableUserTerminatesSessionsCheck : SecurityCheck {
    override fun id() = "7.4.2"
    override fun title() = "Завершение сессий при отключении пользователя"
    override fun description() = "Проверка, что отключение пользователя (enabled=false) немедленно завершает его сессии"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        // Это встроенное поведение Keycloak, которое можно только зафиксировать
        return CheckResult(
            checkId = id(),
            status = CheckStatus.INFO,
            findings = listOf(
                Finding(
                    id = id(),
                    title = "Встроенная функция Keycloak",
                    description = "Keycloak автоматически завершает все активные сессии пользователя при установке enabled=false",
                    severity = Severity.INFO,
                    status = CheckStatus.INFO,
                    realm = context.realmName,
                    evidence = listOf(Evidence("feature", "built-in")),
                    recommendation = "При отключении пользователя через Admin API или консоль все его сессии немедленно становятся недействительными"
                )
            ),
            durationMs = System.currentTimeMillis() - start
        )
    }
}