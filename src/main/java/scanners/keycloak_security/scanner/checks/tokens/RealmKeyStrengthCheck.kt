package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec

@Component
class RealmKeyStrengthCheck : SecurityCheck {

    override fun id() = "11.2.3"
    override fun title() = "Криптографическая стойкость ключей Realm"
    override fun description() =
        "Проверка размера и алгоритмов ключей realm (ASVS V11.2.3, V11.4.3, V11.6.1)"
    override fun severity() = Severity.HIGH

    companion object {
        const val MIN_RSA_KEY_SIZE = 2048
        const val RECOMMENDED_RSA_KEY_SIZE = 3072
        const val MIN_EC_KEY_SIZE = 256

        // HMAC (OCT) ключи используются Keycloak для внутренних нужд (сессии) — это нормально
        val ASYMMETRIC_KEY_TYPES = setOf("RSA", "EC", "OKP")

        val APPROVED_SIGN_ALGORITHMS = setOf(
            "RS256", "RS384", "RS512",
            "ES256", "ES384", "ES512",
            "PS256", "PS384", "PS512",
            "EdDSA"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val keys = context.adminService.getRealmKeys()

            // Фильтруем только асимметричные ключи — OCT (HMAC) ключи используются
            // Keycloak для внутреннего подписания сессий, это штатное поведение
            val asymmetricKeys = keys.filter { it.type in ASYMMETRIC_KEY_TYPES && it.status == "ACTIVE" }

            if (asymmetricKeys.none { it.use?.name == "SIG" }) {
                findings += Finding(
                    id = id(),
                    title = "Нет активных асимметричных ключей подписи",
                    description = "В realm не найдены активные RSA/EC/OKP ключи для подписи токенов.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("activeAsymmetricSignKeys", 0)),
                    recommendation = "Настройте RSA или EC ключи подписи в Realm → Keys → Providers"
                )
            }

            asymmetricKeys.forEach { key ->
                val keyType = key.type ?: return@forEach
                val algorithm = key.algorithm ?: "unknown"
                val keyId = key.kid ?: "unknown"
                val use = key.use?.name ?: "unknown"

                // V11.2.3: Проверяем размер RSA ключа
                if (keyType == "RSA" && key.publicKey != null) {
                    val keySize = getRsaKeySize(key.publicKey)
                    if (keySize != null) {
                        if (keySize < MIN_RSA_KEY_SIZE) {
                            findings += Finding(
                                id = id(),
                                title = "RSA ключ слишком короткий: $keySize бит",
                                description = "Ключ '$keyId' ($use) имеет размер $keySize бит. " +
                                        "Минимум $MIN_RSA_KEY_SIZE бит.",
                                severity = Severity.HIGH,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(
                                    Evidence("keyId", keyId),
                                    Evidence("keySize", keySize),
                                    Evidence("minimum", MIN_RSA_KEY_SIZE)
                                ),
                                recommendation = "Замените ключ на RSA $RECOMMENDED_RSA_KEY_SIZE+ бит"
                            )
                        } else if (keySize < RECOMMENDED_RSA_KEY_SIZE) {
                            findings += Finding(
                                id = id(),
                                title = "RSA ключ $keySize бит (~112 бит security)",
                                description = "Ключ '$keyId' ($use): для 128 бит security рекомендуется RSA $RECOMMENDED_RSA_KEY_SIZE+.",
                                severity = Severity.LOW,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(
                                    Evidence("keyId", keyId),
                                    Evidence("keySize", keySize),
                                    Evidence("recommended", RECOMMENDED_RSA_KEY_SIZE)
                                ),
                                recommendation = "Рассмотрите переход на RSA $RECOMMENDED_RSA_KEY_SIZE бит или ECDSA P-256"
                            )
                        }
                    }
                }

                // V11.4.3: Проверяем алгоритм подписи
                if (use == "SIG" && algorithm !in APPROVED_SIGN_ALGORITHMS) {
                    findings += Finding(
                        id = id(),
                        title = "Неодобренный алгоритм подписи: $algorithm",
                        description = "Ключ '$keyId' использует '$algorithm'. " +
                                "Рекомендуются асимметричные алгоритмы: RS256, ES256 и т.д.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("keyId", keyId),
                            Evidence("algorithm", algorithm)
                        ),
                        recommendation = "Используйте RS256, ES256 или более стойкие алгоритмы"
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }

    private fun getRsaKeySize(publicKeyBase64: String): Int? {
        return try {
            val keyBytes = java.util.Base64.getDecoder().decode(publicKeyBase64)
            val keySpec = X509EncodedKeySpec(keyBytes)
            val keyFactory = KeyFactory.getInstance("RSA")
            val rsaKey = keyFactory.generatePublic(keySpec) as RSAPublicKey
            rsaKey.modulus.bitLength()
        } catch (_: Exception) {
            null
        }
    }
}
