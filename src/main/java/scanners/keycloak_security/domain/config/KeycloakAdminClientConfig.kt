package scanners.keycloak_security.domain.config

import org.keycloak.OAuth2Constants
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
open class KeycloakAdminClientConfig {

    @Bean
    open fun keycloakAdminClient(
        props: KeycloakConnectionProperties
    ): org.keycloak.admin.client.Keycloak {
        return org.keycloak.admin.client.KeycloakBuilder.builder()
            .serverUrl(props.serverUrl)
            .realm(props.realm)
            .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
            .clientId(props.clientId)
            .clientSecret(props.password)
            .build()

//            .clientId(props.clientId)
//            .username(props.username)
//            .password(props.password)
//            .build()
    }
}
