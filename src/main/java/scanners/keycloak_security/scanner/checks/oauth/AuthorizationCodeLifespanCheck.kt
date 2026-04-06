package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class AuthorizationCodeLifespanCheck : SecurityCheck {

    override fun id() = "10.4.3"
    override fun title() = "Authorization code lifespan"
    override fun description() = "Проверка времени жизни authorization code (ASVS V10.4.3)"
    override fun severity() = Severity.MEDIUM

    companion object {
        // ASVS V10.4.3: "up to 10 minutes for L1 and L2 applications and up to 1 minute for L3"
        const val MAX_CODE_LIFESPAN_SECONDS = 600 // 10 минут (L1/L2)
        // Время на заполнение формы логина — отдельная настройка, но тоже не должна быть чрезмерной
        const val MAX_LOGIN_LIFESPAN_SECONDS = 1800 // 30 минут
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()
        val realm = context.adminService.getRealm()

        // accessCodeLifespan — время жизни authorization code после его выдачи
        // (от момента redirect обратно к клиенту до момента обмена на токен)
        val codeLifespan = realm.accessCodeLifespan ?: 60

        if (codeLifespan > MAX_CODE_LIFESPAN_SECONDS) {
            findings += Finding(
                id = id(),
                title = "Слишком большое время жизни authorization code",
                description = "accessCodeLifespan=$codeLifespan секунд. " +
                        "Authorization code должен обмениваться на токен немедленно. " +
                        "Длительное окно увеличивает риск перехвата кода.",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("accessCodeLifespan", codeLifespan),
                    Evidence("recommendedMax", MAX_CODE_LIFESPAN_SECONDS)
                ),
                recommendation = "Установите Access Code Lifespan ≤ $MAX_CODE_LIFESPAN_SECONDS секунд"
            )
        }

        // accessCodeLifespanLogin — время, отведённое на заполнение формы входа
        val loginLifespan = realm.accessCodeLifespanLogin ?: 1800

        if (loginLifespan > MAX_LOGIN_LIFESPAN_SECONDS) {
            findings += Finding(
                id = id(),
                title = "Слишком большое время на прохождение формы входа",
                description = "accessCodeLifespanLogin=$loginLifespan секунд " +
                        "(${loginLifespan / 60} ��инут). Слишком длительное окно для формы входа " +
                        "может позволить атаки через незакрытые формы.",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("accessCodeLifespanLogin", loginLifespan),
                    Evidence("recommendedMax", MAX_LOGIN_LIFESPAN_SECONDS)
                ),
                recommendation = "Установите Access Code Lifespan Login ≤ ${MAX_LOGIN_LIFESPAN_SECONDS / 60} минут"
            )
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
