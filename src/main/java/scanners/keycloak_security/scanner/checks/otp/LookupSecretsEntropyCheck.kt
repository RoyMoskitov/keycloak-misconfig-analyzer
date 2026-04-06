package scanners.keycloak_security.scanner.checks.otp

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class OtpEntropyCheck : SecurityCheck {

    override fun id() = "6.5.4"
    override fun title() = "Минимальная энтропия OTP"
    override fun description() =
        "Проверка, что OTP коды имеют не менее 20 бит энтропии (ASVS)"

    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val findings = mutableListOf<Finding>()

        val digits = realm.otpPolicyDigits ?: 6
        val entropyBits = digits * kotlin.math.log2(10.0)

        if (entropyBits < 20.0) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Недостаточная энтропия OTP",
                    description =
                        "OTP длиной $digits цифр имеет энтропию %.2f бит, что меньше рекомендуемых 20 бит ASVS"
                            .format(entropyBits),
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("otpPolicyDigits", digits),
                        Evidence("calculatedEntropyBits", "%.2f".format(entropyBits))
                    ),
                    recommendation =
                        "Установите otpPolicyDigits ≥ 7 для обеспечения ≥ 20 бит энтропии"
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
