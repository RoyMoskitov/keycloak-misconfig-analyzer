package scanners.keycloak_security.usecase.checks.otp

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class OtpOneTimeCheck : SecurityCheck {

    override fun id() = "6.5.1"
    override fun title() = "Одноразовость OTP"
    override fun description() = "Проверка, что OTP токены используются только один раз"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val otpPolicyType = realm.otpPolicyType ?: "totp"
        val lookAheadWindow = realm.otpPolicyLookAheadWindow ?: 1

        val findings = mutableListOf<Finding>()

        // Проверка типа OTP
        if (otpPolicyType.equals("hotp", ignoreCase = true)) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Используется HOTP вместо TOTP",
                    description = "HOTP (HMAC-based OTP) позволяет повторное использование кодов",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("otpPolicyType", otpPolicyType)
                    ),
                    recommendation = "Используйте TOTP (Time-based OTP) вместо HOTP"
                )
            )
        }

        // Проверка окна предсказания
        if (lookAheadWindow > 0) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Разрешено повторное использование OTP",
                    description = "Окно предсказания OTP установлено в $lookAheadWindow, что может позволять повторное использование",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("otpPolicyLookAheadWindow", lookAheadWindow.toString())
                    ),
                    recommendation = "Установите otpPolicyLookAheadWindow = 0 для гарантии одноразовости OTP"
                )
            )
        }

        // Проверка алгоритма
        val algorithm = realm.otpPolicyAlgorithm ?: "SHA1"
        if (algorithm.equals("SHA1", ignoreCase = true)) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Используется слабый алгоритм SHA1",
                    description = "Алгоритм SHA1 уязвим для коллизий",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("otpPolicyAlgorithm", algorithm)
                    ),
                    recommendation = "Используйте более безопасный алгоритм (SHA256 или SHA512)"
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