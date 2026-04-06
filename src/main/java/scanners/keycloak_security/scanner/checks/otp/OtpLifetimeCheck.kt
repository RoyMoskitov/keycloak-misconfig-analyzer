package scanners.keycloak_security.scanner.checks.otp

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class OtpLifetimeCheck : SecurityCheck {

    override fun id() = "6.5.5"
    override fun title() = "Время жизни OTP"
    override fun description() = "Проверка настроек времени жизни OTP токенов"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val otpPeriod = realm.otpPolicyPeriod ?: 30 // default 30 seconds
        val otpDigits = realm.otpPolicyDigits ?: 6
        val otpCounter = realm.otpPolicyInitialCounter ?: 0

        val findings = mutableListOf<Finding>()

        // Проверка периода OTP
        if (otpPeriod > 30) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Слишком долгое время жизни OTP",
                    description = "Период жизни OTP установлен в $otpPeriod секунд",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("otpPolicyPeriod", otpPeriod.toString())
                    ),
                    recommendation = "Установите otpPolicyPeriod ≤ 30 секунд"
                )
            )
        }

        if (otpPeriod < 30) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Слишком короткое время жизни OTP",
                    description = "Период жизни OTP установлен в $otpPeriod секунд",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("otpPolicyPeriod", otpPeriod.toString())
                    ),
                    recommendation = "Рассмотрите увеличение периода до 30 секунд для удобства пользователей"
                )
            )
        }

        // Проверка количества цифр
        if (otpDigits < 6) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Слишком короткий OTP код",
                    description = "OTP код состоит только из $otpDigits цифр",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("otpPolicyDigits", otpDigits.toString())
                    ),
                    recommendation = "Установите otpPolicyDigits ≥ 6"
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