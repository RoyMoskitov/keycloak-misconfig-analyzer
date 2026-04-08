package scanners.keycloak_security.scanner.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class RefreshTokenRotationCheck : SecurityCheck {

    override fun id() = "7.2.4"
    override fun title() = "Ротация refresh-токенов"
    override fun description() = "Проверка ротации и защиты от replay refresh-токенов (ASVS V7.2.4, V10.4.5, V7.4.1)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val realm = context.adminService.getRealm()

        val revokeRefreshToken = realm.revokeRefreshToken ?: false
        val refreshTokenMaxReuse = realm.refreshTokenMaxReuse ?: 0

        if (!revokeRefreshToken) {
            findings += Finding(
                id = id(),
                title = "Ротация refresh-токенов отключена",
                description = "Опция 'Revoke Refresh Token' выключена. " +
                        "Старые refresh-токены остаются валидными после получения новых. " +
                        "Атакующий, перехвативший refresh token, может использовать его " +
                        "параллельно с легитимным пользователем.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("revokeRefreshToken", false)),
                recommendation = "Включите 'Revoke Refresh Token' в настройках Realm → Tokens"
            )
        }

        if (refreshTokenMaxReuse > 0) {
            findings += Finding(
                id = id(),
                title = "Разрешено повторное использование refresh-токенов",
                description = "refreshTokenMaxReuse=$refreshTokenMaxReuse. Один refresh token может быть " +
                        "использован $refreshTokenMaxReuse раз, что ослабляет защиту от replay-атак.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("refreshTokenMaxReuse", refreshTokenMaxReuse)),
                recommendation = "Установите Refresh Token Max Reuse = 0"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
