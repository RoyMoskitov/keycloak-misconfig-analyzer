package scanners.keycloak_security.domain.config

import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestTemplate

@Configuration
open class RestClientConfig {

    @Bean
    open fun restTemplate(): RestTemplate =
        RestTemplateBuilder().build()
}
