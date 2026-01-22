package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordRotationCheck : SecurityCheck {

    override fun id() = "6.2.10"
    override fun title() = "Принудительная ротация паролей"
    override fun description() = "Проверка настроек принудительной ротации паролей"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val policy = context.adminService.getRealm().passwordPolicy ?: ""

        val rotationPatterns = listOf(
            "forceExpiredPasswordChange\\(",
            "passwordExpiration\\("
        )

        val rotationEnabled = rotationPatterns.any { pattern ->
            Regex(pattern).containsMatchIn(policy)
        }

        return if (rotationEnabled) {
            // Парсим конкретные значения
            val expirationMatch = Regex("passwordExpiration\\((\\d+)\\)").find(policy)
            val expirationDays = expirationMatch?.groupValues?.get(1)?.toInt()

            val description = if (expirationDays != null) {
                "Настроена принудительная ротация паролей каждые $expirationDays дней"
            } else {
                "Обнаружены правила принудительной ротации паролей"
            }

            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = description,
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("passwordPolicy", policy),
                            Evidence("rotationEnabled", "true")
                        ),
                        recommendation = "Отключите принудительную ротацию паролей (forceExpiredPasswordChange, passwordExpiration)"
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