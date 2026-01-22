package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordCompositionRulesCheck : SecurityCheck {

    override fun id() = "6.2.5"
    override fun title() = "Жёсткие композиционные правила пароля"
    override fun description() = "Проверка наличия избыточных правил композиции пароля"
    override fun severity() = Severity.LOW

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val policy = context.adminService.getRealm().passwordPolicy ?: ""

        val compositionRules = listOf(
            "uppercase\\(",
            "lowercase\\(",
            "digits\\(",
            "specialChars\\("
        )

        val enabledRules = compositionRules.filter { rule ->
            Regex(rule).containsMatchIn(policy)
        }.map { rule ->
            // Извлекаем параметры правила
            val pattern = Regex("$rule(\\d+)")
            val match = pattern.find(policy)
            if (match != null) {
                "${rule.replace("\\", "")}${match.groupValues[1]})"
            } else {
                rule.replace("\\", "")
            }
        }

        return if (enabledRules.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Обнаружены жёсткие композиционные правила пароля",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("enabledRules", enabledRules.toString()),
                            Evidence("passwordPolicy", policy.takeIf { it.isNotBlank() } ?: "Не настроена")
                        ),
                        recommendation = "Рассмотрите удаление жёстких композиционных правил. Используйте длинные пароли и blacklist вместо сложных правил."
                    )
                ),
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