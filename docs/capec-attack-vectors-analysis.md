# Анализ векторов атак MITRE CAPEC для Keycloak

## Обоснование выбора CAPEC

CAPEC-658 — это представление (view) каталога CAPEC, содержащее паттерны атак с маппингом на MITRE ATT&CK.
Из ~300 паттернов в CAPEC-658 мы отобрали 20 релевантных для конфигурационной безопасности Keycloak по следующим критериям:

1. **Атака применима к IAM/OAuth/OIDC системам** — не к ОС, hardware или network инфраструктуре
2. **Misconfiguration Keycloak является prerequisite или enabler атаки** — атака становится возможной из-за неправильной конфигурации
3. **Наш сканер может обнаружить prerequisites** — мы проверяем настройки, которые делают атаку возможной

## 20 отобранных атак

### 1. CAPEC-49: Password Brute Forcing
- **ATT&CK:** T1110.001
- **Описание:** Перебор паролей методом полного перебора или по словарю
- **Prerequisites:** Отсутствие rate limiting, слабая парольная политика
- **Связанные проверки:** V6.3.1 (brute force off), V6.2.1 (short passwords), V6.1.2 (no blacklist)

### 2. CAPEC-600: Credential Stuffing
- **ATT&CK:** T1110.004
- **Описание:** Использование утёкших пар логин/пароль из других сервисов
- **Prerequisites:** Нет throttling, нет проверки против утечек, single-factor auth
- **Связанные проверки:** V6.3.1 (brute force off), V6.1.2 (no blacklist), V6.3.3 (no MFA)

### 3. CAPEC-565: Password Spraying
- **ATT&CK:** T1110.003
- **Описание:** Попытка одного распространённого пароля для множества аккаунтов
- **Prerequisites:** Предсказуемые пароли разрешены, нет lockout
- **Связанные проверки:** V6.3.1 (brute force off), V6.2.1 (short passwords), V6.1.2 (no blacklist), V6.3.2 (default accounts)

### 4. CAPEC-55: Rainbow Table Password Cracking
- **ATT&CK:** T1110.002
- **Описание:** Офлайн-перебор хешей паролей через предвычисленные таблицы
- **Prerequisites:** Слабый алгоритм хеширования, мало итераций
- **Связанные проверки:** V11.4.2 (weak hash algorithm), KC-PASS-05 (low iterations)

### 5. CAPEC-70: Try Common/Default Usernames and Passwords
- **ATT&CK:** T1078.001
- **Описание:** Попытка входа с дефолтными credentials (admin/admin, root/root)
- **Prerequisites:** Наличие стандартных аккаунтов с предсказуемыми паролями
- **Связанные проверки:** V6.3.2 (default accounts enabled), V6.2.1 (no min password length)

### 6. CAPEC-115: Authentication Bypass
- **ATT&CK:** T1548
- **Описание:** Обход механизма аутентификации для получения несанкционированного доступа
- **Prerequisites:** Несогласованные authentication pathways, возможность обхода MFA
- **Связанные проверки:** V6.4.3 (reset bypasses MFA), V6.3.4 (inconsistent auth pathways), V10.4.4 (implicit flow enabled)

### 7. CAPEC-2: Inducing Account Lockout (DoS)
- **ATT&CK:** T1531
- **Описание:** Намеренная блокировка аккаунтов жертв через неудачные попытки входа
- **Prerequisites:** Permanent lockout включён
- **Связанные проверки:** V6.3.1 (permanentLockout=true)

### 8. CAPEC-593: Session Hijacking
- **ATT&CK:** T1185, T1550.001
- **Описание:** Перехват или кража активной сессии пользователя
- **Prerequisites:** Нет Secure/HttpOnly на cookies, нет TLS, долгие сессии
- **Связанные проверки:** V3.3.1 (no Secure cookie), V3.3.4 (no HttpOnly), V7.3.1 (no session timeout), V12.2.1 (no HTTPS), V3.3.2 (SameSite=None)

### 9. CAPEC-60: Session Replay
- **ATT&CK:** T1550
- **Описание:** Повторное использование перехваченного session token
- **Prerequisites:** Нет ротации токенов, долгоживущие refresh tokens
- **Связанные проверки:** V7.2.4 (no refresh token rotation), V10.4.8 (no absolute expiration), V7.3.1 (no session timeout)

### 10. CAPEC-196: Session Credential Falsification through Forging
- **ATT&CK:** T1606
- **Описание:** Подделка JWT/session token
- **Prerequisites:** Слабый алгоритм подписи, утечка ключей, alg=none
- **Связанные проверки:** V9.1.1 (alg=none allowed), V9.1.2 (weak algorithms), V11.2.3 (weak keys), V9.1.3 (untrusted key sources)

### 11. CAPEC-633: Token Impersonation
- **ATT&CK:** T1134
- **Описание:** Использование токена одного сервиса для доступа к другому
- **Prerequisites:** Нет audience restriction, fullScopeAllowed
- **Связанные проверки:** V9.2.3 (no aud check), V9.2.4 (no audience mapper), V8.4.1 (fullScopeAllowed)

### 12. CAPEC-94: Adversary in the Middle (AiTM)
- **ATT&CK:** T1557
- **Описание:** Перехват коммуникации между пользователем и Keycloak
- **Prerequisites:** Нет TLS, слабые cipher suites, нет HSTS, HTTP redirect URIs
- **Связанные проверки:** V12.2.1 (no HTTPS), V12.1.1 (weak TLS), V12.1.2 (weak ciphers), V3.4.1 (no HSTS), V10.4.1 (HTTP redirect URIs)

### 13. CAPEC-21: Exploitation of Trusted Identifiers
- **ATT&CK:** T1134
- **Описание:** Использование доверенного идентификатора из одного контекста в другом
- **Prerequisites:** Нет PKCE, Implicit flow (token в URL), нет привязки к сессии
- **Связанные проверки:** V10.2.1 (no PKCE), V10.4.4 (implicit flow), V10.4.2 (code not single-use)

### 14. CAPEC-180: Exploiting Incorrectly Configured ACLs
- **ATT&CK:** T1574
- **Описание:** Использование чрезмерных привилегий из-за неправильных ACL
- **Prerequisites:** Избыточные scopes, fullScopeAllowed, нет consent
- **Связанные проверки:** V10.4.11 (excessive scopes), V8.4.1 (fullScopeAllowed), V10.7.1 (no consent)

### 15. CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies
- **ATT&CK:** T1539
- **Описание:** Кража или модификация cookies через XSS или сетевой перехват
- **Prerequisites:** Нет HttpOnly, нет Secure, SameSite=None
- **Связанные проверки:** V3.3.4 (no HttpOnly), V3.3.1 (no Secure), V3.3.2 (SameSite=None), V12.2.1 (no HTTPS)

### 16. CAPEC-620: Drop Encryption Level
- **ATT&CK:** T1562.010
- **Описание:** Принуждение использовать слабое шифрование или plaintext
- **Prerequisites:** TLS 1.0/1.1 enabled, слабые cipher suites, sslRequired=NONE
- **Связанные проверки:** V12.1.1 (old TLS), V12.1.2 (weak ciphers), V3.3.1 (sslRequired=NONE)

### 17. CAPEC-204: Lifting Sensitive Data Embedded in Cache
- **ATT&CK:** T1005
- **Описание:** Извлечение чувствительных данных из кеша браузера или прокси
- **Prerequisites:** Нет Cache-Control: no-store на sensitive endpoints
- **Связанные проверки:** V14.3.2 (no cache-control)

### 18. CAPEC-541: Application Fingerprinting
- **ATT&CK:** T1592
- **Описание:** Определение версии и технологии приложения для поиска CVE
- **Prerequisites:** Версия раскрывается в headers, admin console доступна
- **Связанные проверки:** V13.4.6 (version exposed), V13.4.4 (TRACE enabled)

### 19. CAPEC-98: Phishing (OAuth context)
- **ATT&CK:** T1566
- **Описание:** Перенаправление пользователя на вредоносный сайт через open redirect
- **Prerequisites:** Wildcard redirect URIs, нет consent, Implicit flow
- **Связанные проверки:** V10.4.1 (wildcard redirects), V10.7.1 (no consent), V10.4.4 (implicit flow), V10.4.7 (open dynamic registration)

### 20. CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs
- **ATT&CK:** T1078
- **Описание:** Доступ к функциональности без должной авторизации
- **Prerequisites:** Direct Access Grants для public clients, нет ограничения grant types
- **Связанные проверки:** V10.4.4 (unnecessary grants), V10.1.1 (token exposure), V8.2.1 (no function-level auth)
