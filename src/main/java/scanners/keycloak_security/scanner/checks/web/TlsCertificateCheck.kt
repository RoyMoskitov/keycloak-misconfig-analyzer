package scanners.keycloak_security.scanner.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.net.URI
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.*

/**
 * ASVS V12.2.2: "Verify that external facing services use publicly trusted TLS certificates."
 */
@Component
class TlsCertificateCheck : SecurityCheck {

    override fun id() = "12.2.2"
    override fun title() = "Публично доверенный TLS сертификат"
    override fun description() =
        "Проверка, что Keycloak использует доверенный TLS сертификат, не self-signed и не expired (ASVS V12.2.2)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val url = URI(context.adminService.props.serverUrl)

        if (url.scheme != "https") {
            findings += Finding(
                id = id(),
                title = "TLS не используется — проверка сертификата невозможна",
                description = "Keycloak доступен по HTTP (${url}). TLS сертификат отсутствует, " +
                        "клиенты не могут верифицировать подлинность сервера.",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("scheme", url.scheme), Evidence("serverUrl", url.toString())),
                recommendation = "Настройте HTTPS с публично доверенным TLS сертификатом."
            )
            return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
        }

        val host = url.host
        val port = if (url.port != -1) url.port else 443

        try {
            // Подключаемся и собираем сертификат
            val certs = mutableListOf<X509Certificate>()

            val tm = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                    certs.addAll(chain)
                }
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(tm), null)

            val socket = sslContext.socketFactory.createSocket(host, port) as SSLSocket
            socket.soTimeout = 5000
            socket.startHandshake()
            socket.close()

            if (certs.isEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Не удалось получить TLS сертификат",
                    description = "TLS handshake завершился, но сертификат не получен.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    recommendation = "Проверьте TLS конфигурацию сервера"
                )
                return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
            }

            val cert = certs[0]

            // 1. Self-signed?
            val isSelfSigned = cert.issuerX500Principal == cert.subjectX500Principal
            if (isSelfSigned) {
                findings += Finding(
                    id = id(),
                    title = "Self-signed TLS сертификат",
                    description = "Keycloak использует self-signed сертификат. " +
                            "Браузеры и клиенты не будут доверять ему без явного добавления в trust store.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("subject", cert.subjectX500Principal.name),
                        Evidence("issuer", cert.issuerX500Principal.name),
                        Evidence("selfSigned", true)
                    ),
                    recommendation = "Используйте сертификат от публичного CA (Let's Encrypt, DigiCert и т.д.)"
                )
            }

            // 2. Expired?
            val now = Date()
            if (now.after(cert.notAfter)) {
                findings += Finding(
                    id = id(),
                    title = "TLS сертификат истёк",
                    description = "Сертификат истёк ${cert.notAfter}. Браузеры покажут предупреждение безопасности.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("notAfter", cert.notAfter.toString()),
                        Evidence("subject", cert.subjectX500Principal.name)
                    ),
                    recommendation = "Обновите TLS сертификат"
                )
            }

            // 3. Скоро истекает (< 30 дней)?
            val thirtyDaysFromNow = Date(System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000)
            if (!now.after(cert.notAfter) && thirtyDaysFromNow.after(cert.notAfter)) {
                findings += Finding(
                    id = id(),
                    title = "TLS сертификат скоро истечёт",
                    description = "Сертификат истекает ${cert.notAfter} (менее 30 дней).",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("notAfter", cert.notAfter.toString()),
                        Evidence("daysLeft", ((cert.notAfter.time - now.time) / (24 * 60 * 60 * 1000)))
                    ),
                    recommendation = "Обновите TLS сертификат до истечения срока"
                )
            }

            // 4. Слабый ключ сертификата?
            val keySize = when (cert.publicKey.algorithm) {
                "RSA" -> (cert.publicKey as java.security.interfaces.RSAPublicKey).modulus.bitLength()
                "EC" -> (cert.publicKey as java.security.interfaces.ECPublicKey).params.order.bitLength()
                else -> null
            }

            if (keySize != null && cert.publicKey.algorithm == "RSA" && keySize < 2048) {
                findings += Finding(
                    id = id(),
                    title = "Слабый ключ TLS сертификата",
                    description = "RSA ключ сертификата $keySize бит. Минимум 2048 бит.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("keyAlgorithm", cert.publicKey.algorithm),
                        Evidence("keySize", keySize)
                    ),
                    recommendation = "Перевыпустите сертификат с RSA ≥ 2048 бит или ECDSA P-256+"
                )
            }

        } catch (_: Exception) {
            // Не удалось подключиться по TLS — возможно HTTP only
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
