package scanners.keycloak_security.scanner.attack

/**
 * Статический реестр из 20 CAPEC атак, релевантных для Keycloak.
 *
 * Каждая атака содержит набор check IDs, findings по которым
 * являются prerequisites данной атаки. Если все (или большинство)
 * prerequisites обнаружены в скане — атака считается возможной.
 */
object AttackVectorRegistry {

    val vectors: List<AttackVector> = listOf(

        // === Credential Attacks ===

        AttackVector(
            capecId = "CAPEC-49",
            name = "Password Brute Forcing",
            description = "Перебор паролей методом полного перебора или по словарю. " +
                    "Отсутствие rate limiting и слабая парольная политика позволяют " +
                    "атакующему подобрать пароль за приемлемое время.",
            attckTechnique = "T1110.001",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Brute force protection отключена",
                "Слабая парольная политика (короткие пароли)"
            ),
            requiredCheckIds = setOf("6.3.1", "6.2.1", "6.6.3")
        ),

        AttackVector(
            capecId = "CAPEC-600",
            name = "Credential Stuffing",
            description = "Использование утёкших пар логин/пароль из других сервисов. " +
                    "Без проверки паролей против баз утечек и без MFA атакующий " +
                    "может получить доступ к аккаунтам с повторно используемыми паролями.",
            attckTechnique = "T1110.004",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Нет brute force protection",
                "Нет blacklist паролей",
                "Нет MFA"
            ),
            requiredCheckIds = setOf("6.3.1", "6.1.2", "6.3.3")
        ),

        AttackVector(
            capecId = "CAPEC-565",
            name = "Password Spraying",
            description = "Попытка одного распространённого пароля для множества аккаунтов. " +
                    "Наличие стандартных аккаунтов и отсутствие blacklist делает атаку эффективной.",
            attckTechnique = "T1110.003",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Стандартные аккаунты активны",
                "Нет blacklist паролей",
                "Нет brute force protection"
            ),
            requiredCheckIds = setOf("6.3.2", "6.1.2", "6.3.1")
        ),

        AttackVector(
            capecId = "CAPEC-55",
            name = "Rainbow Table Password Cracking",
            description = "Офлайн-перебор хешей паролей через предвычисленные таблицы. " +
                    "Слабый алгоритм хеширования или недостаточное количество итераций " +
                    "значительно ускоряет атаку при утечке базы данных.",
            attckTechnique = "T1110.002",
            severity = AttackSeverity.MEDIUM,
            prerequisites = listOf(
                "Слабый алгоритм хеширования",
                "Недостаточно итераций хеширования"
            ),
            requiredCheckIds = setOf("11.4.2", "KC-PASS-05")
        ),

        AttackVector(
            capecId = "CAPEC-70",
            name = "Default Credentials",
            description = "Попытка входа с дефолтными credentials (admin/admin). " +
                    "Стандартные аккаунты с предсказуемыми паролями — простейший вектор входа.",
            attckTechnique = "T1078.001",
            severity = AttackSeverity.CRITICAL,
            prerequisites = listOf(
                "Стандартные аккаунты активны",
                "Слабая или отсутствующая парольная политика"
            ),
            requiredCheckIds = setOf("6.3.2", "6.2.1")
        ),

        // === Authentication Bypass ===

        AttackVector(
            capecId = "CAPEC-115",
            name = "Authentication Bypass via Password Reset",
            description = "Обход MFA через процесс сброса пароля. Если reset flow не требует MFA, " +
                    "атакующий с доступом к email жертвы может войти без второго фактора.",
            attckTechnique = "T1548",
            severity = AttackSeverity.CRITICAL,
            prerequisites = listOf(
                "Сброс пароля обходит MFA",
                "Несогласованные authentication pathways"
            ),
            requiredCheckIds = setOf("6.4.3", "6.3.4")
        ),

        AttackVector(
            capecId = "CAPEC-2",
            name = "Account Lockout DoS",
            description = "Намеренная блокировка аккаунтов жертв через неудачные попытки входа. " +
                    "При включённой перманентной блокировке атакующий может заблокировать " +
                    "любой аккаунт, зная только username.",
            attckTechnique = "T1531",
            severity = AttackSeverity.MEDIUM,
            prerequisites = listOf(
                "Permanent lockout включён"
            ),
            requiredCheckIds = setOf("6.3.1")
        ),

        // === Session Attacks ===

        AttackVector(
            capecId = "CAPEC-593",
            name = "Session Hijacking",
            description = "Перехват или кража активной сессии пользователя через " +
                    "сетевой сниффинг, XSS, или физический доступ к устройству.",
            attckTechnique = "T1185",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Cookies без Secure/HttpOnly",
                "Нет TLS",
                "Долгие сессии без таймаута"
            ),
            requiredCheckIds = setOf("3.3.1", "3.3.4", "7.3.1", "12.2.1")
        ),

        AttackVector(
            capecId = "CAPEC-60",
            name = "Session Replay / Refresh Token Replay",
            description = "Повторное использование перехваченного refresh token. " +
                    "Без ротации и отзыва старый токен остаётся валидным бессрочно.",
            attckTechnique = "T1550",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Нет ротации refresh tokens",
                "Нет абсолютного срока жизни сессии"
            ),
            requiredCheckIds = setOf("7.2.4", "10.4.8", "7.3.1")
        ),

        // === Token Attacks ===

        AttackVector(
            capecId = "CAPEC-196",
            name = "JWT Token Forgery",
            description = "Подделка JWT токена путём использования alg=none, " +
                    "слабых ключей подписи или кражи ключевого материала.",
            attckTechnique = "T1606",
            severity = AttackSeverity.CRITICAL,
            prerequisites = listOf(
                "alg=none разрешён или слабые алгоритмы",
                "Слабые ключи подписи",
                "Ненадёжные источники ключей"
            ),
            requiredCheckIds = setOf("9.1.1", "9.1.2", "11.2.3", "9.1.3")
        ),

        AttackVector(
            capecId = "CAPEC-633",
            name = "Token Cross-Service Abuse",
            description = "Использование токена, выданного одному сервису, для доступа к другому. " +
                    "Без audience restriction и с fullScopeAllowed токен содержит роли всех клиентов.",
            attckTechnique = "T1134",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Нет audience restriction",
                "fullScopeAllowed включён"
            ),
            requiredCheckIds = setOf("9.2.4", "8.4.1")
        ),

        // === Network / Transport Attacks ===

        AttackVector(
            capecId = "CAPEC-94",
            name = "Adversary in the Middle (AiTM)",
            description = "Перехват коммуникации между пользователем и Keycloak. " +
                    "Без TLS атакующий в сети может перехватить credentials, " +
                    "authorization codes и tokens.",
            attckTechnique = "T1557",
            severity = AttackSeverity.CRITICAL,
            prerequisites = listOf(
                "HTTP без TLS",
                "Слабые TLS версии/шифры",
                "Нет HSTS",
                "HTTP redirect URIs"
            ),
            requiredCheckIds = setOf("12.2.1", "12.1.1", "3.4.1", "10.4.1")
        ),

        AttackVector(
            capecId = "CAPEC-620",
            name = "TLS Downgrade Attack",
            description = "Принуждение использовать слабое шифрование (TLS 1.0/1.1) " +
                    "или plaintext HTTP для перехвата данных.",
            attckTechnique = "T1562.010",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Старые версии TLS поддерживаются",
                "Слабые cipher suites",
                "SSL не обязателен"
            ),
            requiredCheckIds = setOf("12.1.1", "12.1.2", "3.3.1")
        ),

        // === OAuth/OIDC Specific ===

        AttackVector(
            capecId = "CAPEC-21",
            name = "OAuth Authorization Code Interception",
            description = "Перехват authorization code через отсутствие PKCE, " +
                    "использование Implicit flow или долгоживущий code.",
            attckTechnique = "T1134",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Нет PKCE",
                "Implicit flow включён",
                "Долгоживущий authorization code"
            ),
            requiredCheckIds = setOf("10.2.1", "10.4.4", "10.4.3")
        ),

        AttackVector(
            capecId = "CAPEC-98",
            name = "OAuth Phishing via Open Redirect",
            description = "Перенаправление пользователя на вредоносный сайт через wildcard redirect URIs. " +
                    "Атакующий регистрирует redirect на свой сервер и получает authorization code.",
            attckTechnique = "T1566",
            severity = AttackSeverity.CRITICAL,
            prerequisites = listOf(
                "Wildcard redirect URIs",
                "Нет consent",
                "Implicit flow"
            ),
            requiredCheckIds = setOf("10.4.1", "10.7.1", "10.4.4")
        ),

        // === Access Control ===

        AttackVector(
            capecId = "CAPEC-180",
            name = "Privilege Escalation via Excessive Scopes",
            description = "Получение избыточных привилегий через неправильно настроенные " +
                    "scopes и роли. fullScopeAllowed включает все роли в токен.",
            attckTechnique = "T1574",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "fullScopeAllowed включён",
                "Избыточные default scopes",
                "Нет consent для запроса scopes"
            ),
            requiredCheckIds = setOf("8.4.1", "10.4.11", "10.7.1")
        ),

        AttackVector(
            capecId = "CAPEC-1",
            name = "Unauthorized API Access via Misconfigured Grants",
            description = "Доступ к API через несанкционированные grant types. " +
                    "Direct Access Grants на public clients позволяют получить токен, " +
                    "минуя стандартный browser-based flow.",
            attckTechnique = "T1078",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Ненужные grant types включены",
                "Token exposure через public clients"
            ),
            requiredCheckIds = setOf("10.4.4", "10.1.1")
        ),

        // === Cookie / Cache ===

        AttackVector(
            capecId = "CAPEC-31",
            name = "Cookie Theft via XSS/Network",
            description = "Кража session cookies через XSS (без HttpOnly) " +
                    "или сетевой перехват (без Secure). SameSite=None разрешает cross-site отправку.",
            attckTechnique = "T1539",
            severity = AttackSeverity.HIGH,
            prerequisites = listOf(
                "Cookies без HttpOnly",
                "Cookies без Secure",
                "SameSite=None"
            ),
            requiredCheckIds = setOf("3.3.4", "3.3.1", "3.3.2")
        ),

        AttackVector(
            capecId = "CAPEC-204",
            name = "Sensitive Data from Cache",
            description = "Извлечение токенов и данных аутентификации из кеша " +
                    "браузера или прокси-сервера.",
            attckTechnique = "T1005",
            severity = AttackSeverity.MEDIUM,
            prerequisites = listOf(
                "Нет Cache-Control: no-store на sensitive endpoints"
            ),
            requiredCheckIds = setOf("14.3.2")
        ),

        // === Reconnaissance ===

        AttackVector(
            capecId = "CAPEC-541",
            name = "Keycloak Fingerprinting",
            description = "Определение версии Keycloak для поиска известных CVE. " +
                    "Информация о версии в headers и admin console помогает атакующему.",
            attckTechnique = "T1592",
            severity = AttackSeverity.LOW,
            prerequisites = listOf(
                "Версия раскрывается в headers или admin console"
            ),
            requiredCheckIds = setOf("13.4.6")
        )
    )
}
