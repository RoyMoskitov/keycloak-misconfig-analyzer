package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V11.2.3: "all cryptographic primitives utilize a minimum of 128-bits of security
 * based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides
 * roughly 128 bits of security where RSA requires a 3072-bit key."
 *
 * ASVS V11.4.3: "hash functions used in digital signatures are collision resistant
 * and have appropriate bit-lengths (output ≥ 256 bits)."
 *
 * ASVS V11.6.1: "only approved cryptographic algorithms and modes of operation are used
 * for key generation and digital signature generation and verification."
 */
@Component
class RealmKeyStrengthCheck : SecurityCheck {

    override fun id() = "11.2.3"
    override fun title() = "Криптографическая стойкость ключей Realm"
    override fun description() =
        "Проверка размера и алгоритмов ключей realm для обеспечения ≥ 128 бит security (ASVS V11.2.3, V11.4.3, V11.6.1)"
    override fun severity() = Severity.HIGH

    companion object {
        // Минимальные размеры ключей для 128 бит security (NIST SP 800-57)
        const val MIN_RSA_KEY_SIZE = 2048       // 112 бит security, минимально допустимый
        const val RECOMMENDED_RSA_KEY_SIZE = 3072 // 128 бит security, рекомендуемый
        const val MIN_EC_KEY_SIZE = 256          // ~128 бит security

        // Алгоритмы подписи, использующие SHA-1 (collision-broken)
        val SHA1_ALGORITHMS = setOf("SHA1withRSA", "SHA1withECDSA")

        // Одобренные алгоритмы подписи
        val APPROVED_SIGN_ALGORITHMS = setOf(
            "RS256", "RS384", "RS512",
            "ES256", "ES384", "ES512",
            "PS256", "PS384", "PS512",
            "EdDSA"
        )

        // Одобренные типы ключей
        val APPROVED_KEY_TYPES = setOf("RSA", "EC", "OKP")
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val keys = context.adminService.getRealmKeys()
            val activeSignKeys = keys.filter { it.status == "ACTIVE" && it.use?.name == "SIG" }
            val activeEncKeys = keys.filter { it.status == "ACTIVE" && it.use?.name == "ENC" }

            if (activeSignKeys.isEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Нет активных ключей подписи",
                    description = "В realm не найдены активные ключи подписи (SIG). " +
                            "Без ключей подписи токены не могут быть верифицированы.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("activeSignKeys", 0)),
                    recommendation = "Настройте ключи подписи в Realm → Keys → Providers"
                )
            }

            // Проверяем все активные ключи
            (activeSignKeys + activeEncKeys).forEach { key ->
                val keyType = key.type ?: "unknown"
                val algorithm = key.algorithm ?: "unknown"
                val keyId = key.kid ?: "unknown"
                val use = key.use?.name ?: "unknown"

                // 1. V11.6.1: Проверяем тип ключа
                if (keyType !in APPROVED_KEY_TYPES) {
                    findings += Finding(
                        id = id(),
                        title = "Неодобренный тип ключа: $keyType",
                        description = "Ключ '$keyId' ($use) использует тип '$keyType', " +
                                "который не входит в список одобренных.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("keyId", keyId),
                            Evidence("keyType", keyType),
                            Evidence("use", use),
                            Evidence("approvedTypes", APPROVED_KEY_TYPES.joinToString())
                        ),
                        recommendation = "Используйте ключи типа RSA, EC или OKP (EdDSA)"
                    )
                }

                // 2. V11.2.3: Проверяем размер ключа
                val keySize = key.publicKey?.let { estimateKeySize(keyType, it) }

                if (keyType == "RSA" && keySize != null) {
                    if (keySize < MIN_RSA_KEY_SIZE) {
                        findings += Finding(
                            id = id(),
                            title = "RSA ключ слишком короткий: $keySize бит",
                            description = "Ключ '$keyId' ($use) имеет размер $keySize бит. " +
                                    "RSA ключи менее $MIN_RSA_KEY_SIZE бит считаются небезопасными.",
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
                            title = "RSA ключ не обеспечивает 128 бит security",
                            description = "Ключ '$keyId' ($use) имеет размер $keySize бит " +
                                    "(~112 бит security). Для 128 бит security нужен RSA $RECOMMENDED_RSA_KEY_SIZE+.",
                            severity = Severity.MEDIUM,
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

                // 3. V11.4.3: Проверяем алгоритм подписи на collision resistance
                if (use == "SIG" && algorithm !in APPROVED_SIGN_ALGORITHMS) {
                    findings += Finding(
                        id = id(),
                        title = "Неодобренный алгоритм подписи: $algorithm",
                        description = "Ключ '$keyId' использует алгоритм '$algorithm' для подписи. " +
                                "Для цифровых подписей требуются collision-resistant хеши " +
                                "с выходом ≥ 256 бит (SHA-256+).",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("keyId", keyId),
                            Evidence("algorithm", algorithm),
                            Evidence("approved", APPROVED_SIGN_ALGORITHMS.joinToString())
                        ),
                        recommendation = "Используйте RS256, ES256 или более стойкие алгоритмы"
                    )
                }
            }

            // 4. Проверяем наличие ключей разных поколений (признак ротации)
            val allSignKeys = keys.filter { it.use?.name == "SIG" }
            val passiveKeys = allSignKeys.filter { it.status == "PASSIVE" }
            if (allSignKeys.isNotEmpty() && passiveKeys.isEmpty() && allSignKeys.size == 1) {
                findings += Finding(
                    id = id(),
                    title = "Отсутствуют признаки ротации ключей",
                    description = "Найден только один ключ подписи без passive/rotated версий. " +
                            "Регулярная ротация ключей снижает ущерб при компрометации.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("activeSignKeys", activeSignKeys.size),
                        Evidence("passiveSignKeys", 0)
                    ),
                    recommendation = "Настройте политику ротации ключей (Realm → Keys → Providers)"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }

    private fun estimateKeySize(keyType: String, publicKeyBase64: String): Int? {
        return try {
            // Base64 публичного ключа — примерная оценка размера по длине
            val keyBytes = java.util.Base64.getDecoder().decode(publicKeyBase64)
            when (keyType) {
                "RSA" -> keyBytes.size * 8 // Приблизительно: DER-encoded public key ≈ key size
                "EC" -> when {
                    keyBytes.size <= 64 -> 256   // P-256
                    keyBytes.size <= 96 -> 384   // P-384
                    else -> 521                   // P-521
                }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }
}
