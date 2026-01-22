package scanners.keycloak_security.domain.config

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(KeycloakConnectionProperties::class)
open class KeycloakAuditConfig
