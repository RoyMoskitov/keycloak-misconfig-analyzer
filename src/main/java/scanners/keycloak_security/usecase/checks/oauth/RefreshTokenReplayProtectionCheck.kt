package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class RefreshTokenReplayProtectionCheck : SecurityCheck {

    override fun id() = "10.4.5"
    override fun title() = "Защита от повторного использования Refresh Token"
    override fun description() =
        "Проверка включения refresh token rotation и запрета повторного использования refresh token"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val revokeEnabled = realm.revokeRefreshToken == true
        val maxReuse = realm.refreshTokenMaxReuse

        return if (!revokeEnabled || maxReuse != 0) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Refresh token могут быть переиспользованы",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("revokeRefreshToken", revokeEnabled),
                            Evidence("refreshTokenMaxReuse", maxReuse)
                        ),
                        recommendation =
                            "Включите revokeRefreshToken и установите refreshTokenMaxReuse = 0"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
