package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

@Component
class JwtAudienceRestrictionCheck : SecurityCheck {

    override fun id() = "9.2.4"
    override fun title() = "Ограничение аудитории токена"
    override fun description() =
        "Проверка, что access token явно ограничен по audience и не может быть переиспользован между сервисами"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            val client = context.adminService.getClientRepresentation()
                ?: return clientNotFound(start, context.realmName)

            val clientId = client.clientId ?: "unknown"

            val audienceMappers = client.protocolMappers
                ?.filter { it.protocolMapper == "oidc-audience-mapper" }
                ?: emptyList()

            if (audienceMappers.isEmpty()) {
                findings += Finding(
                    id(),
                    "Аудитория токена не ограничена",
                    "Для клиента '$clientId' не настроен Audience Protocol Mapper",
                    Severity.MEDIUM,
                    CheckStatus.DETECTED,
                    context.realmName,
                    evidence = listOf(Evidence("clientId", clientId)),
                    recommendation =
                        "Настройте Audience Protocol Mapper для явного указания целевых сервисов."
                )
            } else {
                audienceMappers.forEach { mapper ->
                    val cfg = mapper.config ?: emptyMap()
                    val aud = cfg["included.client.audience"]
                        ?: cfg["included.custom.audience"]
                        ?: ""

                    if (aud.isBlank()) {
                        findings += Finding(
                            id(),
                            "Пустая аудитория",
                            "Маппер '${mapper.name}' не содержит конкретных значений audience",
                            Severity.MEDIUM,
                            CheckStatus.DETECTED,
                            context.realmName,
                            evidence = listOf(
                                Evidence("clientId", clientId),
                                Evidence("mapper", mapper.name ?: "unnamed")
                            ),
                            recommendation =
                                "Укажите конкретные client_id целевых сервисов."
                        )
                    }
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

    private fun clientNotFound(start: Long, realm: String) =
        CheckResult(
            checkId = id(),
            status = CheckStatus.ERROR,
            findings = listOf(
                Finding(
                    id(),
                    "Клиент не найден",
                    "Не удалось получить client representation",
                    Severity.HIGH,
                    CheckStatus.ERROR,
                    realm
                )
            ),
            durationMs = System.currentTimeMillis() - start
        )
}
