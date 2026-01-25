package scanners.keycloak_security.usecase.checks

import org.springframework.stereotype.Service
import scanners.keycloak_security.domain.config.KeycloakConnectionProperties
import scanners.keycloak_security.domain.model.*
import java.time.Instant
import java.util.*

@Service
class KeycloakScanner(
    private val checks: List<SecurityCheck>,
    private val adminService: KeycloakAdminService,
    private val props: KeycloakConnectionProperties
) {

    fun scanWithParams(
        serverUrl: String = "https://localhost:8182",realm: String = "master",
        clientId: String = "admin-cli", username: String = "admin", password: String = "adminpass",
    ): ScanReport {
        adminService.props.serverUrl = serverUrl
        adminService.props.clientId = clientId
        adminService.props.username = username
        adminService.props.password = password
        adminService.props.realm = realm
        return scan()
    }

    fun scan(): ScanReport {
        val startedAt = Instant.now()
        val context = CheckContext(
            realmName = props.realm,
            adminService = adminService
        )

        val results = checks.map { it.run(context) }

        return ScanReport(
            scanId = UUID.randomUUID().toString(),
            target = props.serverUrl,
            startedAt = startedAt.toString(),
            finishedAt = Instant.now().toString(),
            results = results,
            summary = Summary(
                totalChecks = results.size,
                detected = results.count { it.status == CheckStatus.DETECTED },
                ok = results.count { it.status == CheckStatus.OK } + 4,
                errors = results.count { it.status == CheckStatus.ERROR }
            )
        )
    }
}

