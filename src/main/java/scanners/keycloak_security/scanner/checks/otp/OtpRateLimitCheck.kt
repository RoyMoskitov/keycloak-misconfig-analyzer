package scanners.keycloak_security.scanner.checks.otp

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class OtpRateLimitCheck : SecurityCheck {

    override fun id() = "6.6.3"
    override fun title() = "Rate limit для OTP"
    override fun description() = "Проверка ограничений скорости для OTP аутентификации (ASVS V6.6.3)"
    override fun severity() = Severity.HIGH

    companion object {
        // При 6-значном OTP и 30с окне — без rate limit атакующий может перебрать
        // значительную часть кодового пространства (10^6 = 1M комбинаций)
        const val MIN_FAILURE_FACTOR = 3
        const val MAX_FAILURE_FACTOR = 10
        const val MIN_QUICK_LOGIN_WAIT = 5
        const val MIN_WAIT_INCREMENT = 30
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val realm = context.adminService.getRealm()

        val bruteForceEnabled = realm.isBruteForceProtected ?: false

        // Keycloak не имеет отдельного rate limit для OTP —
        // защита от перебора OTP обеспечивается общей Brute Force Detection
        if (!bruteForceEnabled) {
            findings += Finding(
                id = id(),
                title = "Brute Force Detection отключена — OTP не защищён от перебора",
                description = "Keycloak использует общий механизм Brute Force Detection для ограничения " +
                        "попыток OTP. При отключённой защите атакующий может неограниченно перебирать " +
                        "OTP-коды. Для 6-значного TOTP с 30-секундным окном это позволяет проверить " +
                        "значительную часть из 1 000 000 возможных комбинаций.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("bruteForceProtected", false)),
                recommendation = "Включите Brute Force Detection в Realm → Security Defenses"
            )
            return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
        }

        val failureFactor = realm.failureFactor ?: 0
        val minimumQuickLoginWaitSeconds = realm.minimumQuickLoginWaitSeconds ?: 0
        val waitIncrement = realm.waitIncrementSeconds ?: 0

        // Для OTP важен низкий failureFactor, т.к. кодовое пространство ограничено
        if (failureFactor > MAX_FAILURE_FACTOR) {
            findings += Finding(
                id = id(),
                title = "Слишком высокий порог блокировки для OTP",
                description = "failureFactor=$failureFactor — при 6-значном OTP каждая попытка имеет " +
                        "вероятность 1/1000000. С $failureFactor допустимыми попытками за один период " +
                        "вероятность угадывания составляет ${failureFactor}/1000000.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("failureFactor", failureFactor),
                    Evidence("recommendedMax", MAX_FAILURE_FACTOR)
                ),
                recommendation = "Для защиты OTP установите failureFactor ≤ $MAX_FAILURE_FACTOR"
            )
        }

        if (minimumQuickLoginWaitSeconds < MIN_QUICK_LOGIN_WAIT) {
            findings += Finding(
                id = id(),
                title = "Короткая задержка между быстрыми попытками OTP",
                description = "minimumQuickLoginWaitSeconds=$minimumQuickLoginWaitSeconds. " +
                        "Без достаточной задержки автоматизированные инструменты могут " +
                        "перебирать OTP-коды с высокой скоростью до достижения failureFactor.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("minimumQuickLoginWaitSeconds", minimumQuickLoginWaitSeconds),
                    Evidence("recommendedMin", MIN_QUICK_LOGIN_WAIT)
                ),
                recommendation = "Установите minimumQuickLoginWaitSeconds ≥ $MIN_QUICK_LOGIN_WAIT"
            )
        }

        if (waitIncrement < MIN_WAIT_INCREMENT) {
            findings += Finding(
                id = id(),
                title = "Малый инкремент задержки после неудачных OTP",
                description = "waitIncrementSeconds=$waitIncrement. Прогрессивная задержка " +
                        "менее $MIN_WAIT_INCREMENT секунд позволяет быстро возобновлять попытки перебора.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("waitIncrementSeconds", waitIncrement),
                    Evidence("recommendedMin", MIN_WAIT_INCREMENT)
                ),
                recommendation = "Установите waitIncrementSeconds ≥ $MIN_WAIT_INCREMENT"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
