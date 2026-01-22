package scanners.keycloak_security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class KeycloakSecurityScannerApplication {

    public static void main(String[] args) {
        SpringApplication.run(KeycloakSecurityScannerApplication.class, args);
    }

}
