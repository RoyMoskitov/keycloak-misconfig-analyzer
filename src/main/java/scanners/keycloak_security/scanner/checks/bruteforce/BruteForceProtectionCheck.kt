package scanners.keycloak_security.scanner.checks.bruteforce

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class BruteForceProtectionCheck : SecurityCheck {

    override fun id() = "6.3.1"
    override fun title() = "Защита от Brute Force"
    override fun description() = "Проверка настроек защиты от атак перебором и credential stuffing"
    override fun severity() = Severity.HIGH

    companion object {
        // NIST SP 800-63B рекомендует блокировку после 100 попыток как максимум,
        // CIS Benchmark для Keycloak рекомендует 5-10
        const val MAX_REASONABLE_FAILURE_FACTOR = 30
        // Минимальное время блокировки — 60 секунд (OWASP рекомендует progressive delay)
        const val MIN_WAIT_INCREMENT_SECONDS = 60
        // Максимальное время блокировки должно быть ≥ 5 минут для эффективной защиты
        const val MIN_MAX_FAILURE_WAIT_SECONDS = 300
        // Время сброса счётчика неудач — если < 15 минут, атакующий может обходить защиту паузами
        const val MIN_MAX_DELTA_TIME_SECONDS = 900
        // Защита от быстрых автоматизированных попыток — минимум 1 секунда
        const val MIN_QUICK_LOGIN_WAIT_SECONDS = 1
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val realm = context.adminService.getRealm()

        val bruteForceEnabled = realm.isBruteForceProtected ?: false
        val permanentLockout = realm.isPermanentLockout ?: false
        val failureFactor = realm.failureFactor ?: 0
        val waitIncrementSeconds = realm.waitIncrementSeconds ?: 0
        val maxFailureWaitSeconds = realm.maxFailureWaitSeconds ?: 0
        val maxDeltaTimeSeconds = realm.maxDeltaTimeSeconds ?: 0
        val minimumQuickLoginWaitSeconds = realm.minimumQuickLoginWaitSeconds ?: 0
        val quickLoginCheckMilliSeconds = realm.quickLoginCheckMilliSeconds ?: 0L

        // 1. Основная проверка: включена ли защита вообще
        if (!bruteForceEnabled) {
            findings += Finding(
                id = id(),
                title = title(),
                description = "Защита от brute force отключена. " +
                        "Атакующий может неограниченно перебирать пароли без блокировки учётной записи.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("bruteForceProtected", false)),
                recommendation = "Включите Brute Force Detection в настройках Realm → Security Defenses → Brute Force Detection"
            )
            // Если защита выключена, остальные параметры не имеют смысла
            return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
        }

        // 2. Порог блокировки (failureFactor)
        if (failureFactor > MAX_REASONABLE_FAILURE_FACTOR) {
            findings += Finding(
                id = id(),
                title = "Слишком высокий порог блокировки",
                description = "Допускается $failureFactor неудачных попыток до блокировки. " +
                        "Это позволяет атакующему перебрать значительное количество паролей.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("failureFactor", failureFactor),
                    Evidence("рекомендуемый максимум", MAX_REASONABLE_FAILURE_FACTOR)
                ),
                recommendation = "Установите failureFactor в диапазоне 5–$MAX_REASONABLE_FAILURE_FACTOR"
            )
        }

        // 3. Permanent lockout — риск DoS
        if (permanentLockout) {
            findings += Finding(
                id = id(),
                title = "Включена перманентная блокировка учётных записей",
                description = "При permanentLockout=true атакующий может заблокировать аккаунт жертвы " +
                        "намеренно, вводя неверные пароли (Account Lockout DoS).",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("permanentLockout", true)),
                recommendation = "Используйте временную блокировку с прогрессивной задержкой вместо перманентной. " +
                        "Перманентная блокировка создаёт вектор DoS-атаки на пользователей."
            )
        }

        // 4. Прогрессивная задержка (waitIncrementSeconds)
        if (waitIncrementSeconds < MIN_WAIT_INCREMENT_SECONDS) {
            findings += Finding(
                id = id(),
                title = "Слишком короткий инкремент задержки",
                description = "waitIncrementSeconds=$waitIncrementSeconds сек. " +
                        "Короткая прогрессивная задержка позволяет атакующему быстро возобновлять попытки.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("waitIncrementSeconds", waitIncrementSeconds),
                    Evidence("рекомендуемый минимум", MIN_WAIT_INCREMENT_SECONDS)
                ),
                recommendation = "Установите waitIncrementSeconds ≥ $MIN_WAIT_INCREMENT_SECONDS для эффективной прогрессивной задержки"
            )
        }

        // 5. Максимальное время блокировки
        if (!permanentLockout && maxFailureWaitSeconds < MIN_MAX_FAILURE_WAIT_SECONDS) {
            findings += Finding(
                id = id(),
                title = "Короткое максимальное время блокировки",
                description = "maxFailureWaitSeconds=$maxFailureWaitSeconds сек. " +
                        "При временной блокировке максимальное время ожидания менее ${MIN_MAX_FAILURE_WAIT_SECONDS / 60} минут " +
                        "может быть недостаточным для предотвращения brute force атак.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("maxFailureWaitSeconds", maxFailureWaitSeconds),
                    Evidence("рекомендуемый минимум", MIN_MAX_FAILURE_WAIT_SECONDS)
                ),
                recommendation = "Увеличьте maxFailureWaitSeconds до $MIN_MAX_FAILURE_WAIT_SECONDS+ секунд (${MIN_MAX_FAILURE_WAIT_SECONDS / 60}+ минут)"
            )
        }

        // 6. Время сброса счётчика неудач (maxDeltaTimeSeconds)
        if (maxDeltaTimeSeconds < MIN_MAX_DELTA_TIME_SECONDS) {
            findings += Finding(
                id = id(),
                title = "Быстрый сброс счётчика неудачных попыток",
                description = "maxDeltaTimeSeconds=$maxDeltaTimeSeconds сек. " +
                        "Если счётчик неудач сбрасывается быстрее чем за ${MIN_MAX_DELTA_TIME_SECONDS / 60} минут, " +
                        "атакующий может обходить защиту, делая паузы между сериями попыток (slow brute force).",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("maxDeltaTimeSeconds", maxDeltaTimeSeconds),
                    Evidence("рекомендуемый минимум", MIN_MAX_DELTA_TIME_SECONDS)
                ),
                recommendation = "Установите maxDeltaTimeSeconds ≥ $MIN_MAX_DELTA_TIME_SECONDS (${MIN_MAX_DELTA_TIME_SECONDS / 60} минут)"
            )
        }

        // 7. Защита от быстрых автоматизированных попыток
        if (minimumQuickLoginWaitSeconds < MIN_QUICK_LOGIN_WAIT_SECONDS) {
            findings += Finding(
                id = id(),
                title = "Не настроена задержка для быстрых попыток входа",
                description = "minimumQuickLoginWaitSeconds=$minimumQuickLoginWaitSeconds. " +
                        "Без задержки между быстрыми попытками автоматизированные инструменты " +
                        "могут атаковать с максимальной скоростью до достижения failureFactor.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("minimumQuickLoginWaitSeconds", minimumQuickLoginWaitSeconds),
                    Evidence("quickLoginCheckMilliSeconds", quickLoginCheckMilliSeconds)
                ),
                recommendation = "Установите minimumQuickLoginWaitSeconds ≥ $MIN_QUICK_LOGIN_WAIT_SECONDS"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
