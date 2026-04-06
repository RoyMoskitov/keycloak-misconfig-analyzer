package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class AuthorizationCodeSingleUseCheck : SecurityCheck {

    override fun id() = "10.4.2"
    override fun title() = "Authorization code single-use"
    override fun description() =
        "Проверка одноразового использования authorization code (ASVS V10.4.2)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        // ASVS V10.4.2: "authorization code can be used only once for a token request.
        // For the second valid request with an authorization code that has already been used,
        // the authorization server must reject a token request and revoke any issued tokens."
        //
        // Keycloak обеспечивает single-use authorization code по умолчанию —
        // это встроенное поведение, которое нельзя отключить через конфигурацию.
        //
        // Однако мы можем проверить связанные настройки, которые влияют на безопасность
        // authorization code flow:

        val realm = context.adminService.getRealm()

        // 1. Проверяем включён ли revoke refresh token — ASVS требует, чтобы при повторном
        //    использовании кода все ранее выданные токены были отозваны.
        //    revokeRefreshToken обеспечивает инфраструктуру для отзыва токенов.
        val revokeRefreshToken = realm.revokeRefreshToken ?: false
        if (!revokeRefreshToken) {
            findings += Finding(
                id = id(),
                title = "Отзыв токенов не включён",
                description = "ASVS V10.4.2 требует, чтобы при повторном использовании authorization code " +
                        "все ранее выданные токены были отозваны. Опция 'Revoke Refresh Token' отключена, " +
                        "что ослабляет механизм обнаружения replay-атак.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("revokeRefreshToken", false)),
                recommendation = "Включите 'Revoke Refresh Token' для полного соответствия V10.4.2"
            )
        }

        // 2. Проверяем время жизни authorization code — короткий код снижает окно для replay
        val codeLifespan = realm.accessCodeLifespan ?: 60
        if (codeLifespan > 60) {
            findings += Finding(
                id = id(),
                title = "Authorization code живёт дольше 60 секунд",
                description = "accessCodeLifespan=$codeLifespan секунд. Хотя Keycloak обеспечивает " +
                        "single-use кодов, более длительное время жизни увеличивает окно, " +
                        "в течение которого перехваченный код может быть использован первым.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("accessCodeLifespan", codeLifespan)),
                recommendation = "Для максимальной безопасности установите Access Code Lifespan ≤ 60 секунд"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
