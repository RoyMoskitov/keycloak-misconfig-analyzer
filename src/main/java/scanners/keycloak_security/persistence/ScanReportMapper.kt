package scanners.keycloak_security.persistence

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.persistence.dto.ScanReportSummaryDto
import scanners.keycloak_security.persistence.entity.ScanFindingEntity
import scanners.keycloak_security.persistence.entity.ScanReportEntity
import java.time.Instant

@Component
class ScanReportMapper(private val objectMapper: ObjectMapper) {

    fun toEntity(report: ScanReport, realm: String): ScanReportEntity {
        val entity = ScanReportEntity(
            scanId = report.scanId,
            target = report.target,
            realm = realm,
            startedAt = Instant.parse(report.startedAt),
            finishedAt = report.finishedAt?.let { Instant.parse(it) },
            totalChecks = report.summary.totalChecks,
            detected = report.summary.detected,
            ok = report.summary.ok,
            errors = report.summary.errors
        )

        report.results.flatMap { it.findings }.forEach { finding ->
            entity.findings += ScanFindingEntity(
                report = entity,
                checkId = finding.id,
                title = finding.title,
                description = finding.description,
                severity = finding.severity,
                status = finding.status,
                realm = finding.realm,
                clientId = finding.clientId,
                recommendation = finding.recommendation,
                evidenceJson = if (finding.evidence.isNotEmpty())
                    objectMapper.writeValueAsString(finding.evidence)
                else null
            )
        }

        return entity
    }

    fun toModel(entity: ScanReportEntity): ScanReport {
        val findings = entity.findings.map { toFinding(it) }
        val grouped = findings.groupBy { it.id }

        val results = grouped.map { (checkId, checkFindings) ->
            val worstStatus = when {
                checkFindings.any { it.status == CheckStatus.ERROR } -> CheckStatus.ERROR
                checkFindings.any { it.status == CheckStatus.DETECTED } -> CheckStatus.DETECTED
                else -> CheckStatus.OK
            }
            CheckResult(
                checkId = checkId,
                status = worstStatus,
                findings = checkFindings
            )
        }

        return ScanReport(
            scanId = entity.scanId,
            target = entity.target,
            startedAt = entity.startedAt.toString(),
            finishedAt = entity.finishedAt?.toString(),
            results = results,
            summary = Summary(
                totalChecks = entity.totalChecks,
                detected = entity.detected,
                ok = entity.ok,
                errors = entity.errors
            )
        )
    }

    fun toFinding(entity: ScanFindingEntity): Finding {
        val evidence = if (!entity.evidenceJson.isNullOrBlank()) {
            try {
                objectMapper.readValue<List<Evidence>>(entity.evidenceJson)
            } catch (_: Exception) {
                emptyList()
            }
        } else {
            emptyList()
        }

        return Finding(
            id = entity.checkId,
            title = entity.title,
            description = entity.description,
            severity = entity.severity,
            status = entity.status,
            realm = entity.realm,
            clientId = entity.clientId,
            evidence = evidence,
            recommendation = entity.recommendation
        )
    }

    fun toSummaryDto(entity: ScanReportEntity) = ScanReportSummaryDto(
        scanId = entity.scanId,
        target = entity.target,
        realm = entity.realm,
        startedAt = entity.startedAt,
        finishedAt = entity.finishedAt,
        totalChecks = entity.totalChecks,
        detected = entity.detected,
        ok = entity.ok,
        errors = entity.errors
    )
}
