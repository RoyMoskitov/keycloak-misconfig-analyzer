package scanners.keycloak_security.grpc

import io.grpc.ManagedChannelBuilder
import jakarta.annotation.PostConstruct
import jakarta.annotation.PreDestroy
import io.grpc.ManagedChannel
import org.slf4j.LoggerFactory
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import scanners.keycloak_security.config.KeycloakConnectionProperties
import scanners.keycloak_security.scanner.SecurityCheck

/**
 * Discovers external gRPC check modules on startup.
 * For each configured module, connects via gRPC, calls ListChecks(),
 * and creates GrpcCheckAdapter beans that participate in scanning.
 */
@Configuration
@EnableConfigurationProperties(ExternalModuleProperties::class)
open class ExternalModuleRegistrar(
    private val moduleProps: ExternalModuleProperties,
    private val keycloakProps: KeycloakConnectionProperties
) {
    private val logger = LoggerFactory.getLogger(ExternalModuleRegistrar::class.java)
    private val channels = mutableListOf<ManagedChannel>()

    @Bean
    open fun externalChecks(): List<SecurityCheck> {
        if (moduleProps.modules.isEmpty()) {
            logger.info("No external gRPC modules configured")
            return emptyList()
        }

        val checks = mutableListOf<SecurityCheck>()

        moduleProps.modules.forEach { config ->
            try {
                logger.info("Connecting to external module '${config.name}' at ${config.host}:${config.port}")

                val channel = ManagedChannelBuilder
                    .forAddress(config.host, config.port)
                    .usePlaintext()
                    .build()
                channels += channel

                val stub = ExternalCheckServiceGrpc.newBlockingStub(channel)

                val response = stub.listChecks(ListChecksRequest.getDefaultInstance())
                logger.info("Module '${config.name}' provides ${response.checksCount} checks: " +
                        response.checksList.joinToString { it.id })

                response.checksList.forEach { meta ->
                    checks += GrpcCheckAdapter(meta, stub) {
                        GrpcConnectionParams(
                            serverUrl = keycloakProps.serverUrl,
                            realm = keycloakProps.realm,
                            clientId = keycloakProps.clientId,
                            username = keycloakProps.username,
                            password = keycloakProps.password
                        )
                    }
                }

            } catch (e: Exception) {
                logger.warn("Failed to connect to module '${config.name}': ${e.message}")
            }
        }

        logger.info("Registered ${checks.size} external checks from ${moduleProps.modules.size} modules")
        return checks
    }

    @PreDestroy
    fun shutdown() {
        channels.forEach { it.shutdownNow() }
    }
}
