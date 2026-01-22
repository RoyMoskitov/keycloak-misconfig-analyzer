package scanners.keycloak_security.usecase.checks.web

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import java.net.URI
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

@Component
class TlsVersionCheck : SecurityCheck {

    override fun id() = "12.1.1"
    override fun title() = "Поддерживаемые версии TLS"
    override fun description() =
        "Проверка того, что Keycloak принимает только TLS 1.2 и TLS 1.3, а устаревшие версии отключены"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        val url = URI(context.adminService.props.serverUrl)
        val host = url.host
        val port = if (url.port != -1) url.port else 443

        val supported = mutableMapOf<String, Boolean>()

        listOf("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3").forEach { protocol ->
            supported[protocol] = supportsTls(host, port, protocol)
        }

        val insecureEnabled =
            supported["TLSv1"] == true || supported["TLSv1.1"] == true
        val tls12Missing = supported["TLSv1.2"] != true

        return if (insecureEnabled || tls12Missing) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Обнаружены небезопасные или некорректные версии TLS",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = supported.map {
                            Evidence(it.key, it.value)
                        },
                        recommendation = buildString {
                            append("Отключите TLS 1.0 и TLS 1.1. ")
                            append("Минимальной версией должна быть TLS 1.2, ")
                            append("TLS 1.3 рекомендуется сделать приоритетной.")
                        }
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                durationMs = System.currentTimeMillis() - start
            )
        }
    }

    private fun supportsTls(host: String, port: Int, protocol: String): Boolean {
        return try {
            val context = SSLContext.getInstance(protocol)
            context.init(null, null, null)

            val socket = context.socketFactory
                .createSocket(host, port) as SSLSocket

            socket.enabledProtocols = arrayOf(protocol)
            socket.startHandshake()
            socket.close()

            true
        } catch (ex: Exception) {
            false
        }
    }
}
