package scanners.keycloak_security.scanner

import scanners.keycloak_security.model.*

object SecurityCheckHelper {

    fun buildCheckResult(
        checkId: String,
        checkTitle: String,
        findings: List<Finding>,
        start: Long,
        realmName: String
    ): CheckResult {
        findings.forEach { it.realm = realmName }

        val detectedFindings = findings.filter { it.status == CheckStatus.DETECTED }

        val status = when {
            detectedFindings.any { it.severity >= Severity.HIGH } -> CheckStatus.DETECTED
            detectedFindings.isNotEmpty() -> CheckStatus.DETECTED
            findings.any { it.status == CheckStatus.WARNING } -> CheckStatus.WARNING
            findings.any { it.status == CheckStatus.INFO } -> CheckStatus.INFO
            else -> CheckStatus.OK
        }

        val finalFindings = findings

        return CheckResult(
            checkId = checkId,
            status = status,
            findings = finalFindings,
            durationMs = System.currentTimeMillis() - start
        )
    }

    fun createErrorResult(
        checkId: String,
        checkTitle: String,
        e: Exception,
        start: Long,
        realmName: String
    ): CheckResult {
        return CheckResult(
            checkId = checkId,
            status = CheckStatus.ERROR,
            findings = listOf(
                Finding(
                    id = checkId,
                    title = checkTitle,
                    description = "Ошибка при выполнении проверки: ${e.message}",
                    severity = Severity.HIGH,
                    status = CheckStatus.ERROR,
                    realm = realmName,
                    evidence = listOf(
                        Evidence("error", e.message ?: "Unknown"),
                        Evidence("errorType", e.javaClass.simpleName)
                    ),
                    recommendation = "Проверьте подключение к Keycloak и права доступа API"
                )
            ),
            durationMs = System.currentTimeMillis() - start
        )
    }
}