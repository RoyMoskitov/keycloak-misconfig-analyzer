package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V6.3.4: "Verify that, if the application includes multiple authentication pathways,
 * there are no undocumented pathways and that security controls and authentication strength
 * are enforced consistently."
 *
 * В Keycloak: проверяем что все authentication flows используют согласованные
 * уровни безопасности и нет нестандартных потоков без MFA.
 */
@Component
class AuthPathwayConsistencyCheck : SecurityCheck {

    override fun id() = "6.3.4"
    override fun title() = "Согласованность authentication pathways"
    override fun description() =
        "Проверка, что все пути аутентификации обеспечивают согласованный уровень безопасности (ASVS V6.3.4)"
    override fun severity() = Severity.MEDIUM

    companion object {
        val MFA_AUTHENTICATORS = setOf(
            "auth-otp-form",
            "direct-grant-validate-otp",
            "webauthn-authenticator",
            "webauthn-authenticator-passwordless",
            "auth-recovery-authn-code-form"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()
            val allExecutions = context.adminService.getAllAuthenticationExecutions()

            // Определяем какие flows назначены realm
            val browserFlowAlias = realm.browserFlow ?: "browser"
            val directGrantFlowAlias = realm.directGrantFlow ?: "direct grant"
            val resetCredFlowAlias = realm.resetCredentialsFlow ?: "reset credentials"
            val registrationFlowAlias = realm.registrationFlow ?: "registration"

            val assignedFlows = setOf(browserFlowAlias, directGrantFlowAlias, resetCredFlowAlias, registrationFlowAlias)

            // Проверяем browser flow на наличие MFA
            val browserExecutions = allExecutions[browserFlowAlias] ?: emptyList()
            val browserHasMfa = browserExecutions.any { exec ->
                exec.providerId in MFA_AUTHENTICATORS &&
                        exec.requirement in listOf("REQUIRED", "ALTERNATIVE", "CONDITIONAL")
            }

            // Если browser flow имеет MFA, проверяем что direct grant тоже
            if (browserHasMfa) {
                val directGrantExecutions = allExecutions[directGrantFlowAlias] ?: emptyList()
                val directGrantHasMfa = directGrantExecutions.any { exec ->
                    exec.providerId in MFA_AUTHENTICATORS
                }

                if (!directGrantHasMfa) {
                    findings += Finding(
                        id = id(),
                        title = "Direct Grant flow не требует MFA",
                        description = "Browser flow '$browserFlowAlias' требует MFA, " +
                                "но Direct Grant flow '$directGrantFlowAlias' — нет. " +
                                "Атакующий может обойти MFA, используя password grant (Direct Access Grants).",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("browserFlow", browserFlowAlias),
                            Evidence("browserFlowHasMfa", true),
                            Evidence("directGrantFlow", directGrantFlowAlias),
                            Evidence("directGrantFlowHasMfa", false)
                        ),
                        recommendation = "Добавьте MFA в Direct Grant flow или отключите " +
                                "Direct Access Grants для всех клиентов"
                    )
                }
            }

            // Проверяем наличие кастомных (не стандартных) flows
            val standardFlows = setOf(
                "browser", "direct grant", "reset credentials", "registration",
                "first broker login", "docker auth", "http challenge"
            )

            val customFlows = allExecutions.keys.filter { flowAlias ->
                flowAlias !in standardFlows &&
                        !flowAlias.startsWith("first broker login") &&
                        flowAlias !in assignedFlows
            }

            if (customFlows.isNotEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Обнаружены кастомные authentication flows",
                    description = "${customFlows.size} нестандартных flows: ${customFlows.joinToString()}. " +
                            "Кастомные flows могут иметь ослабленные контроли безопасности.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("customFlows", customFlows.joinToString()),
                        Evidence("count", customFlows.size)
                    ),
                    recommendation = "Проверьте, что все кастомные flows обеспечивают " +
                            "согласованный уровень безопасности с основным browser flow"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
