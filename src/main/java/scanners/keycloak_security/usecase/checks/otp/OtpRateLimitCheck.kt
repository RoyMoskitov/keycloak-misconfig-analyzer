package scanners.keycloak_security.usecase.checks.otp

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class OtpRateLimitCheck : SecurityCheck {

    override fun id() = "6.6.3"
    override fun title() = "Rate limit для OTP"
    override fun description() = "Проверка ограничений скорости для OTP аутентификации"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val failureFactor = realm.failureFactor ?: 0
        val minimumQuickLoginWaitSeconds = realm.minimumQuickLoginWaitSeconds ?: 60
        val waitIncrement = realm.waitIncrementSeconds ?: 60

        val findings = mutableListOf<Finding>()

        if (failureFactor <= 0) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Не настроен лимит неудачных попыток",
                    description = "Отсутствует ограничение на количество неудачных попыток OTP",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("failureFactor", failureFactor.toString())
                    ),
                    recommendation = "Установите failureFactor ≥ 3"
                )
            )
        } else if (failureFactor < 3) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Слишком низкий лимит неудачных попыток",
                    description = "Лимит неудачных попыток OTP установлен в $failureFactor",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("failureFactor", failureFactor.toString())
                    ),
                    recommendation = "Увеличьте failureFactor до 5-10 для лучшей защиты"
                )
            )
        }

        // Проверка времени ожидания
        if (minimumQuickLoginWaitSeconds < 5) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Слишком короткая задержка после неудачи",
                    description = "Минимальная задержка после неудачной попытки всего $minimumQuickLoginWaitSeconds секунд",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("minimumQuickLoginWaitSeconds", minimumQuickLoginWaitSeconds.toString())
                    ),
                    recommendation = "Установите minimumQuickLoginWaitSeconds ≥ 5 секунд"
                )
            )
        }

        // Проверка инкремента времени ожидания
        if (waitIncrement < 30) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Слишком малый инкремент времени ожидания",
                    description = "Инкремент времени ожидания при неудачах всего $waitIncrement секунд",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("waitIncrement", waitIncrement.toString())
                    ),
                    recommendation = "Установите waitIncrement ≥ 30 секунд для эффективной защиты от перебора"
                )
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