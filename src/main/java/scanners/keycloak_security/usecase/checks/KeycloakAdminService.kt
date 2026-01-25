package scanners.keycloak_security.usecase.checks

import jakarta.ws.rs.ForbiddenException
import lombok.extern.slf4j.Slf4j
import org.keycloak.admin.client.resource.ClientResource
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.ClientScopeRepresentation
import org.keycloak.representations.idm.IdentityProviderRepresentation
import org.keycloak.representations.idm.KeysMetadataRepresentation
import org.slf4j.LoggerFactory
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.stereotype.Service
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestTemplate
import scanners.keycloak_security.domain.config.KeycloakConnectionProperties
import scanners.keycloak_security.domain.model.TokenResponse
import org.springframework.http.MediaType
import java.lang.System.Logger
import kotlin.math.log

@Service
class KeycloakAdminService(
    private val keycloak: org.keycloak.admin.client.Keycloak,
    val props: KeycloakConnectionProperties,
    private val restTemplate: RestTemplate
) {
    private val logger = LoggerFactory.getLogger(KeycloakAdminService::class.java)
    //private val realmResource by lazy { keycloak.realm(props.realm) }

    fun realmResource() = keycloak.realm(props.realm)
    fun getRealm(): org.keycloak.representations.idm.RealmRepresentation {
        return keycloak.realm(props.realm).toRepresentation()
    }

    fun getClients(): List<org.keycloak.representations.idm.ClientRepresentation> {
        return keycloak.realm(props.realm).clients().findAll()
    }

    fun getAuthenticationFlows() =
        keycloak.realm(props.realm).flows()

    fun getRequiredActions(): List<org.keycloak.representations.idm.RequiredActionProviderRepresentation> {
        return try {
            keycloak.realm(props.realm).flows().requiredActions
        } catch (e: Exception) {
            logger.error("Ошибка при получении required actions: ${e.message}")
            emptyList()
        }
    }

    fun getUsers(): List<org.keycloak.representations.idm.UserRepresentation> {
        return try {
            keycloak.realm(props.realm).users().list()
        } catch (e: Exception) {
            logger.error("Ошибка при получении пользователей: ${e.message}")
            emptyList()
        }
    }

    fun getClientResource(): org.keycloak.admin.client.resource.ClientResource? {
        val clients = realmResource().clients().findByClientId(props.clientId)
        return clients.firstOrNull()?.let { realmResource().clients().get(it.id) }
    }

    fun getClientRepresentation(): org.keycloak.representations.idm.ClientRepresentation? {
        return realmResource().clients().findByClientId(props.clientId).firstOrNull()
    }

    fun getAllAuthenticationExecutions(): Map<String, List<org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation>> {
        val result = mutableMapOf<String, List<org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation>>()
        try {
            val flows = realmResource().flows().flows ?: return result

            flows.forEach { flow ->
                if (flow.alias != null) {
                    val executions = realmResource().flows().getExecutions(flow.alias)
                    if (executions != null) {
                        result[flow.alias] = executions
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Ошибка при получении всех executions: ${e.message}")
        }
        return result
    }

    fun getAuthenticatorConfig(configId: String): org.keycloak.representations.idm.AuthenticatorConfigRepresentation? {
        return try {
            keycloak.realm(props.realm).flows().getAuthenticatorConfig(configId)
        } catch (e: Exception) {
            logger.error("Ошибка при получении конфигурации аутентификатора $configId: ${e.message}")
            null
        }
    }

    fun canRevokeUserSessions(): Boolean {
        return try {
            // Проверяем доступность endpoint для отзыва сессий
            val testResponse = realmResource().users().list()
            true
        } catch (e: ForbiddenException) {
            logger.error("Нет прав для управления пользователями: ${e.message}")
            false
        } catch (e: Exception) {
            logger.error("Ошибка при проверке прав: ${e.message}")
            false
        }
    }

    fun isAccountConsoleAvailable(): Boolean {
        return try {
            // Проверяем существование клиента account-console
            val accountClient = realmResource().clients().findByClientId("account-console").firstOrNull()
            accountClient?.isEnabled ?: false
        } catch (e: Exception) {
            logger.error("Ошибка при проверке Account Console: ${e.message}")
            false
        }
    }
    fun getClientSessionOverrides(): Map<String, Pair<Int?, Int?>> {
        val result = mutableMapOf<String, Pair<Int?, Int?>>()
        try {
            val clients = realmResource().clients().findAll()
            clients.forEach { client ->
                val clientId = client.clientId ?: return@forEach
                val idle = client.attributes?.get("client.session.idle.timeout")?.toIntOrNull()
                val max = client.attributes?.get("client.session.max.lifespan")?.toIntOrNull()
                if (idle != null || max != null) {
                    result[clientId] = Pair(idle, max)
                }
            }
        } catch (e: Exception) {
            logger.error("Ошибка при получении client overrides: ${e.message}")
        }
        return result
    }


    fun getIdentityProviders(): List<IdentityProviderRepresentation> {
        return try {
            // Используем identityProviders().findAll() для получения списка[citation:6]
            realmResource().identityProviders().findAll()
        } catch (e: Exception) {
            logger.error("Ошибка при получении Identity Providers: ${e.message}")
            emptyList()
        }
    }

    fun getKeysMetadata(): KeysMetadataRepresentation? {
        return try {
            realmResource().keys().keyMetadata
        } catch (e: Exception) {
            logger.error("Ошибка при получении публичного ключа realm: ${e.message}")
            null
        }
    }

    fun isUsingExternalKeys(): Boolean {
        return try {
            val keysMetadata = getKeysMetadata()
            // Проверяем, есть ли ключи с внешними URL
            keysMetadata?.keys?.any { key ->
                key.certificate?.startsWith("http") == true ||
                        key.publicKey?.startsWith("http") == true
            } ?: false
        } catch (e: Exception) {
            logger.error("Ошибка при проверке внешних ключей: ${e.message}")
            false
        }
    }

    fun getRealmPublicKey(): String? {
        return try {
            val keysMetadata = getRealmKeys()
            val activeKey = keysMetadata.find { key ->
                key.use.name == "SIG" && key.status == "ACTIVE"
            }
            activeKey?.status
        } catch (e: Exception) {
            logger.error("Ошибка при получении публичного ключа realm: ${e.message}")
            null
        }
    }

    fun getAccessToken(): TokenResponse {

        val tokenUrl =
            "${props.serverUrl}/realms/${props.realm}/protocol/openid-connect/token"

        val headers = HttpHeaders().apply {
            contentType = MediaType.APPLICATION_FORM_URLENCODED
        }

        val body = LinkedMultiValueMap<String, String>().apply {
            add("grant_type", "password")
            add("client_id", props.clientId)
            add("username", props.username)
            add("password", props.password)
        }

        val request = HttpEntity(body, headers)

        val response = restTemplate.postForEntity(
            tokenUrl,
            request,
            TokenResponse::class.java
        )

        return response.body
            ?: throw IllegalStateException("Не удалось получить access token")
    }

    fun getRealmKeys(): List<org.keycloak.representations.idm.KeysMetadataRepresentation.KeyMetadataRepresentation> {
        return try {
            keycloak
                .realm(props.realm)
                .keys()
                .getKeyMetadata()
                .keys
        } catch (e: Exception) {
            logger.error("Ошибка при получении ключей realm: ${e.message}")
            emptyList()
        }
    }

    fun getClientScope(realmId: String, scopeId: String): ClientScopeRepresentation {
        return keycloak.realm(realmId).clientScopes().get(scopeId).toRepresentation()
    }


}
