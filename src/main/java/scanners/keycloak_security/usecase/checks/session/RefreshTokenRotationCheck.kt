package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class RefreshTokenRotationCheck : SecurityCheck {

    override fun id() = "7.2.4"
    override fun title() = "Ротация refresh-токенов"
    override fun description() = "Проверка включения ротации и ограничения повторного использования refresh-токенов"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        // Получаем настройки revokeRefreshToken и refreshTokenMaxReuse
        // Эти поля управляют поведением refresh-токенов [citation:5][citation:7]
        val revokeRefreshToken = realm.revokeRefreshToken ?: false
        val refreshTokenMaxReuse = realm.refreshTokenMaxReuse ?: 0

        val findings = mutableListOf<Finding>()

        // 1. Проверка Revoke Refresh Token
        if (!revokeRefreshToken) {
            findings.add(Finding(
                id = id(),
                title = "Ротация refresh-токенов отключена",
                description = "Опция 'Revoke Refresh Token' выключена. Старые refresh-токены не отзываются при получении новых.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("revokeRefreshToken", "false")),
                recommendation = "Включите 'Revoke Refresh Token' для принудительной ротации refresh-токенов и предотвращения их повторного использования."
            ))
        }

        // 2. Проверка Refresh Token Max Reuse
        if (refreshTokenMaxReuse > 0) {
            findings.add(Finding(
                id = id(),
                title = "Разрешено повторное использование refresh-токенов",
                description = "Refresh Token Max Reuse установлен в $refreshTokenMaxReuse. Токен можно использовать несколько раз.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("refreshTokenMaxReuse", refreshTokenMaxReuse.toString())),
                recommendation = "Установите Refresh Token Max Reuse = 0 для запрета любого повторного использования refresh-токенов."
            ))
        }

        // 3. Комплексная проверка (обе настройки должны быть правильными)
        if (revokeRefreshToken && refreshTokenMaxReuse == 0) {
            // Все правильно - можно добавить информационное сообщение
            return CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                findings = listOf(Finding(
                    id = id(),
                    title = "Ротация refresh-токенов правильно настроена",
                    description = "Revoke Refresh Token включен, Refresh Token Max Reuse = 0.",
                    severity = Severity.LOW,
                    status = CheckStatus.OK,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("revokeRefreshToken", "true"),
                        Evidence("refreshTokenMaxReuse", "0")
                    ),
                    recommendation = null
                )),
                durationMs = System.currentTimeMillis() - start
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