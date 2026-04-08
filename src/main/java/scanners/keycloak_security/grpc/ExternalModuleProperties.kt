package scanners.keycloak_security.grpc

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "scanner.external")
data class ExternalModuleProperties(
    val modules: List<ModuleConfig> = emptyList()
) {
    data class ModuleConfig(
        val name: String = "",
        val host: String = "localhost",
        val port: Int = 9090
    )
}
