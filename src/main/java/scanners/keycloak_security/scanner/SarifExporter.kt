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
                defaultConfiguration = SarifRuleConfiguration(level = "error"),
                helpUri = "https://owasp.org/www-project-application-security-verification-standard/",
                properties = SarifRuleProperties(
                    tags = listOf("security", "keycloak", "owasp-asvs")
                )
            )
        }.distinctBy { it.id }

        // Один SARIF result на каждый DETECTED check (агрегация всех findings внутри)
        val results = report.results
            .filter { it.status == CheckStatus.DETECTED }
            .map { check ->
                val firstFinding = check.findings.firstOrNull()
                val findingsCount = check.findings.size

                SarifResult(
                    ruleId = check.checkId,
                    level = "error",
                    message = SarifMessage(
                        text = buildString {
                            append(firstFinding?.description ?: check.checkId)
                            if (findingsCount > 1) {
                                append("\n\nDetected in $findingsCount instances:")
                                check.findings.forEach { f ->
                                    val loc = listOfNotNull(f.realm, f.clientId).joinToString("/")
                                    append("\n- ${if (loc.isNotBlank()) loc else "realm-settings"}: ${f.title}")
                                }
                            }
                            if (firstFinding?.recommendation != null) {
                                append("\n\nRecommendation: ${firstFinding.recommendation}")
                            }
                        }
                    ),
                    locations = listOf(
                        SarifLocation(
                            physicalLocation = SarifPhysicalLocation(
                                artifactLocation = SarifArtifactLocation(
                                    uri = "keycloak-config/${firstFinding?.realm ?: "unknown"}/${firstFinding?.clientId ?: "realm-settings"}.json"
                                )
                            )
                        )
                    ),
                    properties = SarifResultProperties(
                        realm = firstFinding?.realm,
                        clientId = firstFinding?.clientId,
                        severity = firstFinding?.severity?.name,
                        evidence = firstFinding?.evidence?.associate { it.key to it.value?.toString() }
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
