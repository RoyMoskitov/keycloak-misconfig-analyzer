package scanners.keycloak_security.scanner.checks.otp

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class OtpOneTimeCheck : SecurityCheck {

    override fun id() = "6.5.1"
    override fun title() = "Одноразовость OTP"
    override fun description() = "Проверка, что OTP токены используются только один раз (ASVS V6.5.1)"
    override fun severity() = Severity.HIGH

    companion object {
        // lookAheadWindow=1 — дефолт Keycloak, компенсирует clock drift.
        // Значения > 2 существенно расширяют окно для replay-атак.
        const val MAX_SAFE_LOOK_AHEAD_WINDOW = 2
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val realm = context.adminService.getRealm()

        val otpPolicyType = realm.otpPolicyType ?: "totp"
        val lookAheadWindow = realm.otpPolicyLookAheadWindow ?: 1
        val algorithm = realm.otpPolicyAlgorithm ?: "HmacSHA1"

        // 1. HOTP vs TOTP
        if (otpPolicyType.equals("hotp", ignoreCase = true)) {
            findings += Finding(
                id = id(),
                title = "Используется HOTP вместо TOTP",
                description = "HOTP (counter-based) менее безопасен, чем TOTP: код не истекает по времени, " +
                        "что увеличивает окно для replay-атак. Также счётчик может рассинхронизироваться.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("otpPolicyType", otpPolicyType)),
                recommendation = "Переключитесь на TOTP (Time-based OTP) — коды автоматически истекают через 30 секунд"
            )
        }

        // 2. Look-ahead window — только если значительно превышает норму
        if (lookAheadWindow > MAX_SAFE_LOOK_AHEAD_WINDOW) {
            findings += Finding(
                id = id(),
                title = "Широкое окно предсказания OTP",
                description = "lookAheadWindow=$lookAheadWindow — принимаются коды из $lookAheadWindow " +
                        "временных окон. Это расширяет возможность replay-атаки: перехваченный код " +
                        "может быть использован в течение ${lookAheadWindow * 30} секунд вместо 30.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("otpPolicyLookAheadWindow", lookAheadWindow),
                    Evidence("effectiveWindowSeconds", lookAheadWindow * 30),
                    Evidence("recommendedMax", MAX_SAFE_LOOK_AHEAD_WINDOW)
                ),
                recommendation = "Установите otpPolicyLookAheadWindow ≤ $MAX_SAFE_LOOK_AHEAD_WINDOW. " +
                        "Значение 1 (дефолт) достаточно для компенсации clock drift."
            )
        }

        // 3. Алгоритм — HMAC-SHA1 безопасен для TOTP (RFC 6238), но SHA256/SHA512 предпочтительнее
        //    Это информационный finding (LOW), т.к. HMAC-SHA1 не подвержен атакам на коллизии
        if (algorithm.equals("HmacSHA1", ignoreCase = true)) {
            findings += Finding(
                id = id(),
                title = "OTP использует HMAC-SHA1",
                description = "HMAC-SHA1 безопасен для TOTP (не подвержен collision-атакам), " +
                        "однако HMAC-SHA256/SHA512 обеспечивают больший запас стойкости.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("otpPolicyAlgorithm", algorithm)),
                recommendation = "Рассмотрите переход на HmacSHA256 или HmacSHA512 для большего запаса стойкости"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
