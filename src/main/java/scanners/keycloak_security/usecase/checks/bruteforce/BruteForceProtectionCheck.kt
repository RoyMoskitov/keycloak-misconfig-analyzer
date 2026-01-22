package scanners.keycloak_security.usecase.checks.bruteforce

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class BruteForceProtectionCheck : SecurityCheck {

    override fun id() = "6.3.1"
    override fun title() = "Защита от Brute Force"
    override fun description() = "Проверка настроек защиты от атак перебором и credential stuffing"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val bruteForceEnabled = realm.isBruteForceProtected ?: false
        val failureFactor = realm.failureFactor ?: 0
        val maxFailureWaitSeconds = realm.maxFailureWaitSeconds ?: 0
        val minimumQuickLoginWaitSeconds = realm.minimumQuickLoginWaitSeconds ?: 0

        val findings = mutableListOf<Finding>()

        if (!bruteForceEnabled) {
            findings.add(
                Finding(
                    id = id(),
                    title = title(),
                    description = "Защита от brute force отключена",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("bruteForceProtected", "false")),
                    recommendation = "Включите защиту от brute force атак в настройках безопасности Realm"
                )
            )
        }

        if (failureFactor <= 0) {
            findings.add(
                Finding(
                    id = id(),
                    title = title(),
                    description = "Не настроено ограничение количества неудачных попыток",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("failureFactor", failureFactor.toString())),
                    recommendation = "Установите failureFactor > 0 для ограничения неудачных попыток входа"
                )
            )
        }

        // Проверка других параметров как advisory
        if (maxFailureWaitSeconds < 300) { // меньше 5 минут
            findings.add(
                Finding(
                    id = id(),
                    title = "Короткое время блокировки",
                    description = "Время максимальной блокировки ($maxFailureWaitSeconds сек) может быть недостаточным",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("maxFailureWaitSeconds", maxFailureWaitSeconds.toString())),
                    recommendation = "Увеличьте maxFailureWaitSeconds до 300+ секунд (5+ минут)"
                )
            )
        }

        val status = if (findings.any { it.severity >= Severity.MEDIUM }) {
            CheckStatus.DETECTED
        } else if (findings.isNotEmpty()) {
            CheckStatus.WARNING
        } else {
            CheckStatus.OK
        }

        return CheckResult(
            checkId = id(),
            status = status,
            findings = if (status == CheckStatus.OK) {
                listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Настройки защиты от brute force корректны",
                        severity = Severity.LOW,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("bruteForceProtected", bruteForceEnabled.toString()),
                            Evidence("failureFactor", failureFactor.toString()),
                            Evidence("maxFailureWaitSeconds", maxFailureWaitSeconds.toString())
                        ),
                        recommendation = null
                    )
                )
            } else {
                findings
            },
            durationMs = System.currentTimeMillis() - start
        )
    }
}