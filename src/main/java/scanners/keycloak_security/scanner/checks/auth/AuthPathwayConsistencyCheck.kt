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

            val browserFlowAlias = realm.browserFlow ?: "browser"
            val directGrantFlowAlias = realm.directGrantFlow ?: "direct grant"
            val resetCredFlowAlias = realm.resetCredentialsFlow ?: "reset credentials"
            val registrationFlowAlias = realm.registrationFlow ?: "registration"

            val assignedFlows = setOf(browserFlowAlias, directGrantFlowAlias, resetCredFlowAlias, registrationFlowAlias)

            val browserExecutions = allExecutions[browserFlowAlias] ?: emptyList()
            val directGrantExecutions = allExecutions[directGrantFlowAlias] ?: emptyList()

            // Проверяем: MFA только CONDITIONAL (зависит от user config)?
            val browserMfaExecs = browserExecutions.filter { it.providerId in MFA_AUTHENTICATORS }
            val browserHasAnyMfa = browserMfaExecs.any {
                it.requirement in listOf("REQUIRED", "ALTERNATIVE", "CONDITIONAL")
            }

            // MFA считается "unconditional" если есть REQUIRED MFA на уровне 0 (верхний уровень потока)
            // CONDITIONAL sub-flow (level 1+) = MFA зависит от настройки юзера → слабая гарантия
            val browserHasUnconditionalMfa = browserMfaExecs.any {
                it.requirement == "REQUIRED" && (it.level ?: 0) <= 1
            }

            // Проверяем direct grant flow
            val dgMfaExecs = directGrantExecutions.filter { it.providerId in MFA_AUTHENTICATORS }
            val directGrantHasActiveMfa = dgMfaExecs.any {
                it.requirement in listOf("REQUIRED", "ALTERNATIVE", "CONDITIONAL")
            }

            // 1. Browser flow имеет MFA, но только в CONDITIONAL sub-flow
            if (browserHasAnyMfa && !browserHasUnconditionalMfa) {
                findings += Finding(
                    id = id(),
                    title = "MFA в browser flow только условная (CONDITIONAL)",
                    description = "MFA настроена в CONDITIONAL sub-flow, что означает она применяется " +
                            "только если пользователь самостоятельно настроил OTP/WebAuthn. " +
                            "Пользователи без настроенного второго фактора входят только по паролю.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("browserFlow", browserFlowAlias),
                        Evidence("mfaMode", "conditional"),
                        Evidence("mfaAuthenticators", browserMfaExecs.joinToString { "${it.providerId} (${it.requirement})" })
                    ),
                    recommendation = "Сделайте MFA обязательной для всех пользователей, " +
                            "установив CONFIGURE_TOTP как default required action"
                )
            }

            // 2. Browser flow имеет MFA, direct grant — нет
            if (browserHasAnyMfa && !directGrantHasActiveMfa) {
                findings += Finding(
                    id = id(),
                    title = "Direct Grant flow не требует MFA",
                    description = "Browser flow '$browserFlowAlias' требует MFA, " +
                            "но Direct Grant flow '$directGrantFlowAlias' — нет. " +
                            "Атакующий может обойти MFA, используя password grant.",
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

            // 3. Кастомные flows
            val standardFlows = setOf(
                "browser", "direct grant", "reset credentials", "registration",
                "first broker login", "docker auth", "http challenge", "clients"
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
