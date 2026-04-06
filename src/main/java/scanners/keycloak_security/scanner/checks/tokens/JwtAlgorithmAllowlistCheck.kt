package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.service.JwtParser
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

@Component
class JwtAlgorithmAllowlistCheck : SecurityCheck {

    override fun id() = "9.1.2"
    override fun title() = "Разрешённые алгоритмы подписи JWT"
    override fun description() =
        "Проверка использования безопасных и допустимых алгоритмов подписи токенов"
    override fun severity() = Severity.HIGH

    private val allowedAlgorithms = setOf(
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512"
    )

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            val realm = context.adminService.getRealm()
            val activeKeys = context.adminService.getRealmKeys()

            activeKeys
                .filter { it.use.name == "sig" && it.status == "ACTIVE" }
                .forEach { key ->
                    val alg = key.algorithm ?: "unknown"

                    if (alg !in allowedAlgorithms) {
                        findings += Finding(
                            id(),
                            "Используется неподдерживаемый алгоритм подписи",
                            "Обнаружен алгоритм '$alg'",
                            Severity.HIGH,
                            CheckStatus.DETECTED,
                            context.realmName,
                            evidence = listOf(
                                Evidence("keyId", key.kid ?: "unknown"),
                                Evidence("algorithm", alg)
                            ),
                            recommendation =
                                "Ограничьте список алгоритмов подписи безопасными асимметричными алгоритмами (RS256 / ES256)."
                        )
                    }
                }

            CheckResult(
                checkId = id(),
                status = if (findings.isEmpty()) CheckStatus.OK else CheckStatus.DETECTED,
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )

        } catch (e: Exception) {
            createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}
