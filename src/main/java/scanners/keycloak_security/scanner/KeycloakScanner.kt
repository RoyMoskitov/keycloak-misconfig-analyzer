package scanners.keycloak_security.scanner

import org.springframework.stereotype.Service
import scanners.keycloak_security.config.KeycloakConnectionProperties
import scanners.keycloak_security.service.KeycloakAdminService
import scanners.keycloak_security.model.*
import scanners.keycloak_security.persistence.ScanPersistenceService
import java.time.Instant
import java.util.*

@Service
class KeycloakScanner(
    private val checks: List<SecurityCheck>,
    private val adminService: KeycloakAdminService,
    private val props: KeycloakConnectionProperties,
    private val persistenceService: ScanPersistenceService
) {

    fun scanWithParams(
        serverUrl: String, realm: String, clientId: String,
        username: String = "", password: String = "",
        clientSecret: String = "", grantType: String = "password",
        authRealm: String = ""
    ): ScanReport {
        adminService.props.serverUrl = serverUrl
        adminService.props.clientId = clientId
        adminService.props.realm = realm
        adminService.props.grantType = grantType
        adminService.props.authRealm = authRealm

        if (grantType == "client_credentials") {
            adminService.props.clientSecret = clientSecret
            adminService.props.username = ""
            adminService.props.password = ""
        } else {
            adminService.props.username = username
            adminService.props.password = password
            adminService.props.clientSecret = ""
        }

        return scan()
    }

    fun scan(): ScanReport {
        val startedAt = Instant.now()
        val context = CheckContext(
            realmName = props.realm,
            adminService = adminService
        )

        val results = checks.map { it.run(context) }

        val report = ScanReport(
            scanId = UUID.randomUUID().toString(),
            target = props.serverUrl,
            startedAt = startedAt.toString(),
            finishedAt = Instant.now().toString(),
            results = results,
            summary = Summary(
                totalChecks = results.size,
                detected = results.count { it.status == CheckStatus.DETECTED },
                ok = results.count { it.status == CheckStatus.OK },
                errors = results.count { it.status == CheckStatus.ERROR }
            )
        )

        persistenceService.save(report, props.realm)
        return report
    }
}
