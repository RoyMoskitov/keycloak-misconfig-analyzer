# Полный анализ CAPEC-658 для Keycloak Security Scanner

## Методология

**Источник:** CAPEC-658 (ATT&CK Related Patterns) -- view из 177 паттернов атак, имеющих маппинг на MITRE ATT&CK.

**Критерии отбора:** паттерн считается релевантным (YES), если его prerequisites могут быть проверены через:
- Конфигурацию Keycloak realm/client (Admin REST API)
- Поведение HTTP endpoints Keycloak
- Настройки инфраструктуры (TLS, proxy, контейнер)

**Критерии исключения (NO):**
- Физический доступ к оборудованию
- Атаки на ОС / hardware / firmware
- Supply-chain атаки
- Требуется установка malware на endpoint
- Сетевая инфраструктура (BGP, DNS, Bluetooth, cellular)
- Бизнес-логика приложений, не связанная с аутентификацией

**MAYBE** -- пограничные случаи, где связь с конфигурацией Keycloak косвенная.

## Сводка

| Категория | Количество |
|-----------|-----------|
| YES (релевантно) | 35 |
| MAYBE (пограничные) | 19 |
| NO (нерелевантно) | 123 |
| **Итого** | **177** |

## Отобранные 20 атак для сканера

Из 35 YES-паттернов отобраны 20, покрывающих все ключевые категории без дублирования:

| CAPEC | Название | Категория | Почему отобран |
|-------|---------|-----------|---------------|
| CAPEC-49 | Password Brute Forcing | Credential | Прямой маппинг на brute force detection, password policy |
| CAPEC-55 | Rainbow Table Password Cracking | Credential | Маппинг на hash algorithm, iterations |
| CAPEC-70 | Try Common or Default Usernames and Passwords | Credential | Маппинг на default accounts, password policy |
| CAPEC-565 | Password Spraying | Credential | Маппинг на brute force, blacklist, user enumeration |
| CAPEC-600 | Credential Stuffing | Credential | Маппинг на brute force, blacklist, MFA, notifications |
| CAPEC-115 | Authentication Bypass | Auth Bypass | Маппинг на MFA bypass через reset flow, flow inconsistency |
| CAPEC-2 | Inducing Account Lockout | Auth DoS | Маппинг на lockout settings |
| CAPEC-21 | Exploitation of Trusted Identifiers | OAuth/OIDC | Маппинг на PKCE, implicit flow, code lifespan |
| CAPEC-98 | Phishing | OAuth/OIDC | Маппинг на redirect URIs, consent, implicit flow |
| CAPEC-60 | Reusing Session IDs (Session Replay) | Session | Маппинг на token rotation, session lifetime, static secrets |
| CAPEC-593 | Session Hijacking | Session | Маппинг на cookies, TLS, session timeout, token lifespan |
| CAPEC-196 | Session Credential Falsification through Forging | Token | Маппинг на signing algorithm, key strength, client auth |
| CAPEC-633 | Token Impersonation | Token | Маппинг на audience, fullScope, token type confusion |
| CAPEC-94 | Adversary in the Middle (AiTM) | Transport | Маппинг на TLS, HSTS, redirect URIs |
| CAPEC-620 | Drop Encryption Level | Transport | Маппинг на TLS versions, cipher suites, SSL required |
| CAPEC-180 | Exploiting Incorrectly Configured Access Control Security Levels | Access Control | Маппинг на fullScope, default scopes, consent, default roles |
| CAPEC-1 | Accessing Functionality Not Properly Constrained by ACLs | Access Control | Маппинг на grant types, token exposure |
| CAPEC-31 | Accessing/Intercepting/Modifying HTTP Cookies | Web | Маппинг на cookie flags (Secure, HttpOnly, SameSite) |
| CAPEC-204 | Lifting Sensitive Data Embedded in Cache | Web | Маппинг на Cache-Control headers |
| CAPEC-541 | Application Fingerprinting | Recon | Маппинг на version exposure, admin console, health endpoints |

### Не отобранные YES-паттерны (15) -- причины

| CAPEC | Название | Почему не отобран |
|-------|---------|-------------------|
| CAPEC-112 | Brute Force | Дублирует CAPEC-49 (Password Brute Forcing) -- тот же паттерн, более общий |
| CAPEC-114 | Authentication Abuse | Дублирует CAPEC-115 (Authentication Bypass) -- пересекающиеся prerequisites |
| CAPEC-122 | Privilege Abuse | Дублирует CAPEC-180 (Misconfigured Access Control) -- те же check IDs |
| CAPEC-233 | Privilege Escalation | Дублирует CAPEC-180 -- эскалация через те же мисконфигурации |
| CAPEC-150 | Collect Data from Common Resource Locations | Дублирует CAPEC-541 (Fingerprinting) -- те же endpoints |
| CAPEC-158 | Sniffing Network Traffic | Дублирует CAPEC-94 (AiTM) -- TLS mitigates both |
| CAPEC-169 | Footprinting | Дублирует CAPEC-541 -- те же reconnaissance check IDs |
| CAPEC-555 | Remote Services with Stolen Credentials | Дублирует CAPEC-600 (Credential Stuffing) -- те же mitigations |
| CAPEC-560 | Use of Known Domain Credentials | Дублирует CAPEC-600 -- те же mitigations (MFA, brute force) |
| CAPEC-57 | Utilizing REST's Trust in System Resource | Покрыт CAPEC-94 (AiTM) -- подмножество MiTM после SSL termination |
| CAPEC-227 | Sustained Client Engagement | Слабый маппинг на KC -- rate limiting в основном на reverse proxy |
| CAPEC-469 | HTTP DoS | Слабый маппинг -- KC brute force != HTTP flood protection |
| CAPEC-473 | Signature Spoof | Покрыт CAPEC-196 (Token Forging) -- подмножество того же вектора |
| CAPEC-474 | Signature Spoofing by Key Theft | Покрыт CAPEC-196 -- кража ключа = часть forging сценария |
| CAPEC-485 | Signature Spoofing by Key Recreation | Покрыт CAPEC-196 -- слабые алгоритмы = часть forging сценария |
| CAPEC-662 | Adversary in the Browser | Покрыт CAPEC-593 (Session Hijacking) + CAPEC-31 (Cookies) |

## Полный анализ всех 177 паттернов

### YES -- релевантно для Keycloak (35)

| CAPEC | Название | Связь с Keycloak |
|-------|---------|-----------------|
| CAPEC-1 | Accessing Functionality Not Properly Constrained by ACLs | Admin console/API ACLs, client role mappings |
| CAPEC-2 | Inducing Account Lockout | Brute force detection, lockout thresholds |
| CAPEC-21 | Exploitation of Trusted Identifiers | Session/token handling, PKCE, code lifespan |
| CAPEC-31 | Accessing/Intercepting/Modifying HTTP Cookies | Cookie flags (Secure, HttpOnly, SameSite) |
| CAPEC-49 | Password Brute Forcing | Brute force detection, password policy |
| CAPEC-55 | Rainbow Table Password Cracking | Hash algorithm, iterations |
| CAPEC-57 | Utilizing REST's Trust in System Resource | TLS termination, endpoint protection |
| CAPEC-60 | Reusing Session IDs (Session Replay) | Token rotation, session lifetime |
| CAPEC-70 | Try Common or Default Usernames and Passwords | Default accounts, password policy |
| CAPEC-94 | Adversary in the Middle (AiTM) | TLS, HSTS, redirect URIs |
| CAPEC-112 | Brute Force | Brute force detection, lockout |
| CAPEC-114 | Authentication Abuse | Auth flow weaknesses, MFA bypass |
| CAPEC-115 | Authentication Bypass | Misconfigured flows, disabled actions |
| CAPEC-122 | Privilege Abuse | Role mappings, client scopes, admin permissions |
| CAPEC-150 | Collect Data from Common Resource Locations | Well-known endpoints, info disclosure |
| CAPEC-158 | Sniffing Network Traffic | TLS enforcement, secure cookies |
| CAPEC-169 | Footprinting | Endpoint info disclosure, version exposure |
| CAPEC-180 | Exploiting Incorrectly Configured Access Control Security Levels | Roles, scopes, fullScopeAllowed |
| CAPEC-196 | Session Credential Falsification through Forging | JWT signing, key strength |
| CAPEC-204 | Lifting Sensitive Data Embedded in Cache | Cache-Control headers |
| CAPEC-227 | Sustained Client Engagement | Rate limiting, resource exhaustion |
| CAPEC-233 | Privilege Escalation | Role escalation, scope elevation |
| CAPEC-469 | HTTP DoS | HTTP flood, brute force protection |
| CAPEC-473 | Signature Spoof | JWT/SAML signature verification |
| CAPEC-474 | Signature Spoofing by Key Theft | Signing key protection, rotation |
| CAPEC-485 | Signature Spoofing by Key Recreation | Weak signing algorithms |
| CAPEC-541 | Application Fingerprinting | Version exposure, admin console |
| CAPEC-555 | Remote Services with Stolen Credentials | MFA, session policies, brute force |
| CAPEC-560 | Use of Known Domain Credentials | MFA, password policies, brute force |
| CAPEC-565 | Password Spraying | Brute force, blacklist, enumeration |
| CAPEC-593 | Session Hijacking | Session timeouts, cookies, TLS |
| CAPEC-600 | Credential Stuffing | Brute force, blacklist, MFA |
| CAPEC-620 | Drop Encryption Level | TLS versions, cipher suites |
| CAPEC-633 | Token Impersonation | Audience, fullScope, token types |
| CAPEC-662 | Adversary in the Browser | Session cookies, CSP, HTTPS |

### MAYBE -- пограничные (19)

| CAPEC | Название | Почему пограничный |
|-------|---------|-------------------|
| CAPEC-13 | Subverting Environment Variable Values | KC использует env vars (DB, TLS), но это container-level |
| CAPEC-37 | Retrieve Embedded Sensitive Data | Токены могут содержать лишние claims; настраивается через mappers |
| CAPEC-98 | Phishing | Redirect URI validation и CSP ограничивают вектор, но фишинг шире KC |
| CAPEC-125 | Flooding | Rate limiting частично в KC, но основная защита на reverse proxy |
| CAPEC-141 | Cache Poisoning | Cache-Control headers настраиваемы, но cache poisoning шире |
| CAPEC-148 | Content Spoofing | CSP и redirect URIs помогают, но spoofing шире KC |
| CAPEC-267 | Leverage Alternate Encoding | Encoding bypass на auth endpoints -- косвенная связь |
| CAPEC-268 | Audit Log Manipulation | Event logging в KC настраивается, слабая конфигурация помогает атакующему |
| CAPEC-295 | Timestamp Request | KC раскрывает timestamps в токенах/headers |
| CAPEC-383 | Harvesting Information via API Event Monitoring | Admin API может утечь данные если permissions неверны |
| CAPEC-465 | Transparent Proxy Abuse | Proxy settings KC влияют на exposure |
| CAPEC-488 | HTTP Flood | Brute force protection частично помогает |
| CAPEC-497 | File Discovery | Well-known endpoints, admin console exposure |
| CAPEC-528 | XML Flood | SAML (XML) processing, rate limiting |
| CAPEC-543 | Counterfeit Websites | CSP и redirect URI validation помогают |
| CAPEC-571 | Block Logging to Central Repository | Event logging config в KC |
| CAPEC-575 | Account Footprinting | User enumeration prevention settings |
| CAPEC-576 | Group Permission Footprinting | Admin API access controls, role visibility |
| CAPEC-580 | System Footprinting | Headers и error pages раскрывают info |
| CAPEC-639 | Probe System Files | KC config file permissions в container |
| CAPEC-644 | Use of Captured Hashes (Pass The Hash) | Password hash algorithm strength настраивается |
| CAPEC-645 | Use of Captured Tickets (Pass The Ticket) | Kerberos federation settings |
| CAPEC-650 | Upload a Web Shell | Server deployment hardening |
| CAPEC-652 | Use of Known Kerberos Credentials | Kerberos federation и credential policies |

### NO -- нерелевантно (123)

#### Hardware / Physical (22)
CAPEC-438, 439, 440, 457, 516, 520, 522, 531, 532, 537, 539, 638, 646, 665, 671, 672, 674, 675, 677 -- физические атаки на оборудование и firmware

#### Supply Chain (14)
CAPEC-186, 187, 206, 442, 443, 445, 446, 511, 523, 538, 657, 669, 670, 673, 678, 691, 695 -- атаки на цепочку поставок ПО и оборудования

#### OS / Process Level (38)
CAPEC-11, 13, 17, 25, 30, 35, 38, 130, 131, 132, 159, 165, 177, 191, 203, 251, 270, 448, 471, 478, 480, 497, 504, 542, 545, 550, 551, 552, 556, 558, 561, 562, 564, 573, 577, 578, 579, 640, 641, 642, 643, 647, 648, 649, 694, 698 -- инъекции процессов, подмена библиотек, rootkit, registry, файловые атаки

#### Network Infrastructure (15)
CAPEC-125, 142, 292, 295, 300, 309, 312, 313, 481, 482, 489, 490, 609, 616, 666, 668, 697, 700 -- DNS poisoning, port scan, BGP, Bluetooth, cellular, TCP flood

#### Malware / Endpoint (10)
CAPEC-65, 68, 464, 568, 569, 572, 581, 634, 635, 636, 637, 654, 655, 660, 698 -- keylogger, clipboard, screen capture, malicious extensions

#### Social Engineering (unrelated to KC) (3)
CAPEC-163, 407, 543 -- spear phishing (не через KC), pretexting, counterfeit websites (без связи с redirect URIs)

#### Other Irrelevant (5)
CAPEC-19, 127, 509, 528, 571, 574, 576, 580 -- script injection в scripting engines, directory listing, Kerberoasting, XML flood
