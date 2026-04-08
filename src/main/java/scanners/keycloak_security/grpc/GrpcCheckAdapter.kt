package scanners.keycloak_security.grpc

import scanners.keycloak_security.model.CheckContext
import scanners.keycloak_security.model.CheckResult
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.model.Severity as ModelSeverity
import scanners.keycloak_security.model.CheckStatus as ModelCheckStatus
import scanners.keycloak_security.model.Finding as ModelFinding
import scanners.keycloak_security.model.Evidence as ModelEvidence
import scanners.keycloak_security.grpc.Severity as GrpcSeverity
import scanners.keycloak_security.grpc.CheckStatus as GrpcCheckStatus

/**
 * Adapts a single external gRPC check to the internal SecurityCheck interface.
 * One instance per check exposed by an external module.
 */
class GrpcCheckAdapter(
    private val meta: CheckMeta,
    private val stub: ExternalCheckServiceGrpc.ExternalCheckServiceBlockingStub,
    private val connectionProvider: () -> GrpcConnectionParams
) : SecurityCheck {

    override fun id(): String = meta.id
    override fun title(): String = meta.title
    override fun description(): String = meta.description
    override fun severity(): ModelSeverity = mapSeverity(meta.severity)

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val conn = connectionProvider()

        return try {
            val request = RunCheckRequest.newBuilder()
                .setCheckId(meta.id)
                .setServerUrl(conn.serverUrl)
                .setRealm(conn.realm)
                .setClientId(conn.clientId)
                .setUsername(conn.username)
                .setPassword(conn.password)
                .build()

            val response = stub.runCheck(request)

            CheckResult(
                checkId = response.checkId,
                status = mapCheckStatus(response.status),
                findings = response.findingsList.map { mapFinding(it) },
                durationMs = response.durationMs,
                error = response.error.ifEmpty { null }
            )
        } catch (e: Exception) {
            CheckResult(
                checkId = meta.id,
                status = ModelCheckStatus.ERROR,
                findings = listOf(
                    ModelFinding(
                        id = meta.id,
                        title = meta.title,
                        description = "gRPC module error: ${e.message}",
                        severity = ModelSeverity.HIGH,
                        status = ModelCheckStatus.ERROR,
                        realm = conn.realm,
                        recommendation = "Check that the external module is running and accessible"
                    )
                ),
                durationMs = System.currentTimeMillis() - start,
                error = e.message
            )
        }
    }

    private fun mapFinding(f: Finding): ModelFinding {
        return ModelFinding(
            id = f.id,
            title = f.title,
            description = f.description,
            severity = mapSeverity(f.severity),
            status = mapCheckStatus(f.status),
            realm = f.realm.ifEmpty { null },
            clientId = f.clientId.ifEmpty { null },
            evidence = f.evidenceList.map { ModelEvidence(it.key, it.value) },
            recommendation = f.recommendation.ifEmpty { null }
        )
    }

    private fun mapSeverity(s: GrpcSeverity): ModelSeverity = when (s) {
        GrpcSeverity.HIGH -> ModelSeverity.HIGH
        GrpcSeverity.MEDIUM -> ModelSeverity.MEDIUM
        GrpcSeverity.LOW -> ModelSeverity.LOW
        GrpcSeverity.INFO -> ModelSeverity.INFO
        else -> ModelSeverity.LOW
    }

    private fun mapCheckStatus(s: GrpcCheckStatus): ModelCheckStatus = when (s) {
        GrpcCheckStatus.DETECTED -> ModelCheckStatus.DETECTED
        GrpcCheckStatus.OK -> ModelCheckStatus.OK
        GrpcCheckStatus.ERROR -> ModelCheckStatus.ERROR
        GrpcCheckStatus.WARNING -> ModelCheckStatus.WARNING
        else -> ModelCheckStatus.ERROR
    }
}

data class GrpcConnectionParams(
    val serverUrl: String,
    val realm: String,
    val clientId: String,
    val username: String,
    val password: String
)
