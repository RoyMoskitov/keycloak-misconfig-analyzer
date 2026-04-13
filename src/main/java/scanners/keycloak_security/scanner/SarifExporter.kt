package scanners.keycloak_security.scanner

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.stereotype.Component
import scanners.keycloak_security.model.CheckStatus
import scanners.keycloak_security.model.ScanReport
import scanners.keycloak_security.model.Severity

/**
 * Конвертирует ScanReport в формат SARIF v2.1.0.
 *
 * SARIF (Static Analysis Results Interchange Format) — OASIS стандарт,
 * нативно поддерживаемый GitHub Code Scanning, GitLab SAST, Azure DevOps.
 */
@Component
class SarifExporter {

    fun export(report: ScanReport): SarifLog {
        val allFindings = report.results.flatMap { check ->
            check.findings.map { finding -> check.checkId to finding }
        }

        // Собираем уникальные rules из всех check results
        val rules = report.results.map { check ->
            SarifRule(
                id = check.checkId,
                shortDescription = SarifMessage(
                    text = check.findings.firstOrNull()?.title ?: check.checkId
                ),
                fullDescription = SarifMessage(
                    text = check.findings.firstOrNull()?.description ?: ""
                ),
                defaultConfiguration = SarifRuleConfiguration(
                    level = when (check.findings.maxByOrNull { it.severity }?.severity) {
                        Severity.HIGH -> "error"
                        Severity.MEDIUM -> "warning"
                        Severity.LOW -> "note"
                        else -> "note"
                    }
                ),
                helpUri = "https://owasp.org/www-project-application-security-verification-standard/",
                properties = SarifRuleProperties(
                    tags = listOf("security", "keycloak", "owasp-asvs")
                )
            )
        }.distinctBy { it.id }

        // Конвертируем findings в SARIF results
        val results = allFindings
            .filter { (_, finding) -> finding.status == CheckStatus.DETECTED || finding.status == CheckStatus.ERROR }
            .map { (checkId, finding) ->
                SarifResult(
                    ruleId = checkId,
                    level = when (finding.severity) {
                        Severity.HIGH -> "error"
                        Severity.MEDIUM -> "warning"
                        Severity.LOW -> "note"
                        Severity.INFO -> "note"
                    },
                    message = SarifMessage(
                        text = buildString {
                            append(finding.description)
                            if (finding.recommendation != null) {
                                append("\n\nRecommendation: ${finding.recommendation}")
                            }
                        }
                    ),
                    locations = listOf(
                        SarifLocation(
                            physicalLocation = SarifPhysicalLocation(
                                artifactLocation = SarifArtifactLocation(
                                    uri = "keycloak-config/${finding.realm ?: "unknown"}/${finding.clientId ?: "realm-settings"}.json"
                                )
                            )
                        )
                    ),
                    properties = SarifResultProperties(
                        realm = finding.realm,
                        clientId = finding.clientId,
                        severity = finding.severity.name,
                        evidence = finding.evidence.associate { it.key to it.value?.toString() }
                    )
                )
            }

        return SarifLog(
            version = "2.1.0",
            runs = listOf(
                SarifRun(
                    tool = SarifTool(
                        driver = SarifDriver(
                            name = "Keycloak Security Scanner",
                            version = "1.0.0",
                            informationUri = "https://github.com/keycloak-security-scanner",
                            rules = rules
                        )
                    ),
                    results = results,
                    invocations = listOf(
                        SarifInvocation(
                            executionSuccessful = report.results.none { it.status == CheckStatus.ERROR },
                            startTimeUtc = report.startedAt,
                            endTimeUtc = report.finishedAt
                        )
                    )
                )
            )
        )
    }
}

// --- SARIF Data Classes ---

@JsonInclude(JsonInclude.Include.NON_NULL)
data class SarifLog(
    val version: String,
    @JsonProperty("\$schema") val schema: String? = null,
    val runs: List<SarifRun>
)

data class SarifRun(
    val tool: SarifTool,
    val results: List<SarifResult>,
    val invocations: List<SarifInvocation>? = null
)

data class SarifTool(
    val driver: SarifDriver
)

data class SarifDriver(
    val name: String,
    val version: String,
    val informationUri: String? = null,
    val rules: List<SarifRule>
)

data class SarifRule(
    val id: String,
    val shortDescription: SarifMessage,
    val fullDescription: SarifMessage? = null,
    val defaultConfiguration: SarifRuleConfiguration? = null,
    val helpUri: String? = null,
    val properties: SarifRuleProperties? = null
)

data class SarifRuleConfiguration(
    val level: String
)

data class SarifRuleProperties(
    val tags: List<String>? = null
)

data class SarifResult(
    val ruleId: String,
    val level: String,
    val message: SarifMessage,
    val locations: List<SarifLocation>? = null,
    val properties: SarifResultProperties? = null
)

data class SarifResultProperties(
    val realm: String? = null,
    val clientId: String? = null,
    val severity: String? = null,
    val evidence: Map<String, String?>? = null
)

data class SarifMessage(
    val text: String
)

data class SarifLocation(
    val physicalLocation: SarifPhysicalLocation
)

data class SarifPhysicalLocation(
    val artifactLocation: SarifArtifactLocation
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class SarifArtifactLocation(
    val uri: String,
    val uriBaseId: String? = null
)

data class SarifInvocation(
    val executionSuccessful: Boolean,
    val startTimeUtc: String? = null,
    val endTimeUtc: String? = null
)
