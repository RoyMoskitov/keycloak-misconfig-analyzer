package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.URI
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/**
 * ASVS V12.1.2: "Verify that only recommended cipher suites are enabled,
 * with the strongest cipher suites set as preferred."
 */
@Component
class CipherSuitesCheck : SecurityCheck {

    override fun id() = "12.1.2"
    override fun title() = "Рекомендуемые cipher suites"
    override fun description() =
        "Проверка, что используются только безопасные cipher suites с forward secrecy (ASVS V12.1.2)"
    override fun severity() = Severity.HIGH

    companion object {
        // Небезопасные cipher suites
        val WEAK_CIPHERS = setOf(
            "RC4", "DES", "3DES", "DES_CBC", "RC2",
            "NULL", "anon", "EXPORT", "MD5"
        )

        // Cipher suites без forward secrecy (нет DHE/ECDHE)
        val NO_FORWARD_SECRECY_PREFIXES = setOf(
            "TLS_RSA_WITH_",
            "SSL_RSA_WITH_"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val url = URI(context.adminService.props.serverUrl)
        if (url.scheme != "https") {
            return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
        }

        val host = url.host
        val port = if (url.port != -1) url.port else 443

        try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(TrustAllManager), null)

            val socket = sslContext.socketFactory.createSocket(host, port) as SSLSocket
            socket.soTimeout = 5000
            socket.startHandshake()

            val enabledCiphers = socket.session.protocol to socket.session.cipherSuite
            val allSupported = socket.enabledCipherSuites.toList()

            socket.close()

            // 1. Проверяем наличие слабых cipher suites
            val weakFound = allSupported.filter { cipher ->
                WEAK_CIPHERS.any { weak -> cipher.contains(weak, ignoreCase = true) }
            }

            if (weakFound.isNotEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Обнаружены слабые cipher suites",
                    description = "Сервер поддерживает ${weakFound.size} слабых cipher suites: " +
                            "${weakFound.take(5).joinToString()}.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("weakCiphers", weakFound.joinToString()),
                        Evidence("count", weakFound.size)
                    ),
                    recommendation = "Отключите слабые cipher suites (RC4, DES, 3DES, NULL, EXPORT) в keycloak.conf"
                )
            }

            // 2. Проверяем cipher suites без forward secrecy
            val noFsFound = allSupported.filter { cipher ->
                NO_FORWARD_SECRECY_PREFIXES.any { prefix -> cipher.startsWith(prefix) }
            }

            if (noFsFound.isNotEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Cipher suites без forward secrecy",
                    description = "${noFsFound.size} cipher suites не обеспечивают forward secrecy. " +
                            "Без PFS компрометация ключа сервера позволит расшифровать весь прошлый трафик.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("noForwardSecrecyCiphers", noFsFound.take(5).joinToString()),
                        Evidence("count", noFsFound.size)
                    ),
                    recommendation = "Используйте только cipher suites с ECDHE или DHE для forward secrecy"
                )
            }

        } catch (_: Exception) {
            // Не удалось подключиться по TLS
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}

// Shared trust-all manager for TLS checks
private object TrustAllManager : javax.net.ssl.X509TrustManager {
    override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
}
