package scanners.keycloak_security.scanner.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class InvalidateSessionsOnCredentialChangeCheck : SecurityCheck {
    override fun id() = "7.4.3"
    override fun title() = "Завершение сессий при смене учётных данных"
    override fun description() = "Проверка возможности завершения сессий при смене пароля или MFA (ASVS V7.4.3)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()

            // ASVS V7.4.3: "the application gives the option to terminate all other active sessions
            // after a successful change or removal of any authentication factor"

            // В Keycloak механизм завершения сессий при смене credentials обеспечивается через
            // revokeRefreshToken — при отзыве refresh token все сессии теряют возможность обновления
            val revokeRefreshToken = realm.revokeRefreshToken ?: false
            if (!revokeRefreshToken) {
                findings += Finding(
                    id = id(),
                    title = "Отзыв refresh tokens не включён",
                    description = "Опция 'Revoke Refresh Token' отключена. При смене пароля или MFA " +
                            "старые refresh tokens остаются валидными, что позволяет атакующему " +
                            "продолжить использование скомпрометированной сессии.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("revokeRefreshToken", false)),
                    recommendation = "Включите 'Revoke Refresh Token' для инвалидации сессий при смене credentials"
                )
            }

            // Проверяем, что access token не слишком долгоживущий
            // (даже при отзыве refresh token, access token остаётся валидным до истечения)
            val accessTokenLifespan = realm.accessTokenLifespan ?: 300
            if (accessTokenLifespan > 900) { // > 15 минут
                findings += Finding(
                    id = id(),
                    title = "Долгоживущий access token",
                    description = "accessTokenLifespan=$accessTokenLifespan секунд (${accessTokenLifespan / 60} минут). " +
                            "При смене пароля скомпрометированный access token остаётся валидным " +
                            "до истечения, даже если refresh token отозван.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("accessTokenLifespan", accessTokenLifespan)),
                    recommendation = "Сократите Access Token Lifespan до 5-15 минут для минимизации окна атаки"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
