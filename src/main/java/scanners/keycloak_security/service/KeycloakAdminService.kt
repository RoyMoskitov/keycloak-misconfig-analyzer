package scanners.keycloak_security.service

import jakarta.ws.rs.ForbiddenException
import org.keycloak.representations.idm.ClientScopeRepresentation
import org.keycloak.representations.idm.IdentityProviderRepresentation
import org.keycloak.representations.idm.KeysMetadataRepresentation
import org.slf4j.LoggerFactory
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestTemplate
import scanners.keycloak_security.config.KeycloakConnectionProperties
import scanners.keycloak_security.model.TokenResponse

@Service
class KeycloakAdminService(
    val props: KeycloakConnectionProperties,
    private val restTemplate: RestTemplate
) {
    private val logger = LoggerFactory.getLogger(KeycloakAdminService::class.java)

    @Volatile
    private var cachedClient: org.keycloak.admin.client.Keycloak? = null
    @Volatile
    private var cachedClientKey: String? = null

    private fun buildClient(): org.keycloak.admin.client.Keycloak {
        val key = "${props.serverUrl}|${props.realm}|${props.clientId}|${props.username}|${props.grantType}|${props.authRealm}"
        val existing = cachedClient
        if (existing != null && cachedClientKey == key) {
            return existing
        }

        existing?.close()

        val authRealm = props.authRealm.ifBlank {
            if (props.grantType == "client_credentials") props.realm else "master"
        }

        val builder = org.keycloak.admin.client.KeycloakBuilder.builder()
            .serverUrl(props.serverUrl)
            .realm(authRealm)
            .clientId(props.clientId)

        val client = if (props.grantType == "client_credentials") {
            builder
                .grantType(org.keycloak.OAuth2Constants.CLIENT_CREDENTIALS)
                .clientSecret(props.clientSecret)
                .build()
        } else {
            builder
                .username(props.username)
                .password(props.password)
                .build()
        }

        cachedClient = client
        cachedClientKey = key
        return client
    }

    fun invalidateClient() {
        cachedClient?.close()
        cachedClient = null
        cachedClientKey = null
    }

    fun realmResource() = buildClient().realm(props.realm)

    fun getRealm(): org.keycloak.representations.idm.RealmRepresentation {
        return buildClient().realm(props.realm).toRepresentation()
    }

    fun getClients(): List<org.keycloak.representations.idm.ClientRepresentation> {
        return buildClient().realm(props.realm).clients().findAll()
    }

    fun getAuthenticationFlows() =
        buildClient().realm(props.realm).flows()

    fun getRequiredActions(): List<org.keycloak.representations.idm.RequiredActionProviderRepresentation> {
        return try {
            buildClient().realm(props.realm).flows().requiredActions
        } catch (e: Exception) {
            logger.error("Ошибка при получении required actions: ${e.message}")
            emptyList()
        }
    }

    fun getUsers(): List<org.keycloak.representations.idm.UserRepresentation> {
        return try {
            buildClient().realm(props.realm).users().list()
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
            buildClient().realm(props.realm).flows().getAuthenticatorConfig(configId)
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
                key.use?.name.equals("SIG", ignoreCase = true) &&
                        key.status == "ACTIVE" &&
                        key.type in listOf("RSA", "EC", "OKP")
            }
            activeKey?.publicKey
        } catch (e: Exception) {
            logger.error("Ошибка при получении публичного ключа realm: ${e.message}")
            null
        }
    }

    fun getAccessToken(): TokenResponse {
        val authRealm = props.authRealm.ifBlank {
            if (props.grantType == "client_credentials") props.realm else "master"
        }
        val tokenUrl =
            "${props.serverUrl}/realms/$authRealm/protocol/openid-connect/token"

        val headers = HttpHeaders().apply {
            contentType = MediaType.APPLICATION_FORM_URLENCODED
        }

        val body = LinkedMultiValueMap<String, String>().apply {
            if (props.grantType == "client_credentials") {
                add("grant_type", "client_credentials")
                add("client_id", props.clientId)
                add("client_secret", props.clientSecret)
            } else {
                add("grant_type", "password")
                add("client_id", props.clientId)
                add("username", props.username)
                add("password", props.password)
            }
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
            buildClient()
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
        return buildClient().realm(realmId).clientScopes().get(scopeId).toRepresentation()
    }

    fun getClientResourceById(clientUuid: String): org.keycloak.admin.client.resource.ClientResource? {
        return try {
            realmResource().clients().get(clientUuid)
        } catch (e: Exception) {
            logger.error("Ошибка при получении client resource $clientUuid: ${e.message}")
            null
        }
    }

    fun getRealmRoles(): List<org.keycloak.representations.idm.RoleRepresentation> {
        return try {
            realmResource().roles().list()
        } catch (e: Exception) {
            logger.error("Ошибка при получении realm roles: ${e.message}")
            emptyList()
        }
    }

    fun getDefaultRoleComposites(defaultRoleId: String): List<org.keycloak.representations.idm.RoleRepresentation> {
        return try {
            realmResource().rolesById().getRoleComposites(defaultRoleId).toList()
        } catch (e: Exception) {
            logger.error("Ошибка при получении composites для default role: ${e.message}")
            emptyList()
        }
    }
}
