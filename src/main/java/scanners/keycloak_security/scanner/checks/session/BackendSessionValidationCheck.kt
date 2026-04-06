package scanners.keycloak_security.scanner.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

@Component
class BackendSessionValidationCheck : SecurityCheck {
    override fun id() = "7.2.1"
    override fun title() = "Валидация сессий только на backend"
    override fun description() = "Проверка использования подписанных JWT access token'ов для валидации сессий доверенным backend'ом"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val realm = context.adminService.getRealm()
            val findings = mutableListOf<Finding>()

            // 1. Проверка алгоритма подписи токенов по умолчанию
            val sigAlg = realm.defaultSignatureAlgorithm ?: "RS256"
            val safeAlgorithms = listOf("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
            if (!safeAlgorithms.contains(sigAlg)) {
                findings.add(Finding(
                    id = id(),
                    title = "Некорректный алгоритм подписи токенов",
                    description = "Используется алгоритм '$sigAlg'. Токены должны подписываться асимметричными алгоритмами (RS256/ES256).",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("defaultSignatureAlgorithm", sigAlg)),
                    recommendation = "Измените Default Signature Algorithm на RS256, ES256 или другой рекомендованный асимметричный алгоритм."
                ))
            }

            // 2. Проверка времени жизни Access Token (не должен быть слишком долгим)
            val accessTokenLifespan = realm.accessTokenLifespan ?: 300
            if (accessTokenLifespan > 3600) {
                findings.add(Finding(
                    id = id(),
                    title = "Слишком долгое время жизни Access Token",
                    description = "Access Token живет $accessTokenLifespan секунд (${accessTokenLifespan / 60} мин).",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("accessTokenLifespan", "$accessTokenLifespan сек")),
                    recommendation = "Уменьшите Access Token Lifespan до 5-15 минут для снижения риска при компрометации токена."
                ))
            }

            return if (findings.isEmpty()) {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.OK,
                    findings = listOf(Finding(
                        id = id(),
                        title = "Настройки токенов соответствуют требованиям",
                        description = "Используется безопасный алгоритм подписи ($sigAlg), Access Token имеет ограниченное время жизни.",
                        severity = Severity.INFO,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("defaultSignatureAlgorithm", sigAlg),
                            Evidence("accessTokenLifespan", "$accessTokenLifespan сек")
                        ),
                        recommendation = null
                    )),
                    durationMs = System.currentTimeMillis() - start
                )
            } else {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.DETECTED,
                    findings = findings,
                    durationMs = System.currentTimeMillis() - start
                )
            }
        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}