# Полная классификация CAPEC-658 для Keycloak

## Методология

Каждый CAPEC из представления 658 классифицирован по применимости к конфигурационной безопасности Keycloak:

- **SELECTED** — атака релевантна, misconfiguration Keycloak является prerequisite
- **NOT_APPLICABLE** — атака не применима к Keycloak (с указанием причины)

### Категории исключения:
- **OS/INFRA** — атака на уровне ОС, hardware, сети (не приложение)
- **CODE** — атака на исходный код / бинарники (не конфигурация)
- **SUPPLY_CHAIN** — атака на цепочку поставок
- **PHYSICAL** — физический доступ
- **NOT_IAM** — не относится к IAM/OAuth/OIDC
- **BUILT_IN** — Keycloak защищён от этого встроенно
- **NO_CONFIG** — невозможно обнаружить через конфигурационный сканер

---

## Meta Attack Patterns (22)

| CAPEC | Название | Статус | Категория | Обоснование |
|-------|---------|--------|-----------|-------------|
| 21 | Exploitation of Trusted Identifiers | **SELECTED** | — | OAuth code interception, PKCE bypass |
| 25 | Forced Deadlock | NOT_APPLICABLE | OS/INFRA | Deadlock на уровне ОС/threads |
| 94 | Adversary in the Middle | **SELECTED** | — | Перехват трафика без TLS |
| 112 | Brute Force | **SELECTED** | — | Meta-pattern, покрыт через детальные (49, 565, 600) |
| 114 | Authentication Abuse | **SELECTED** | — | Meta-pattern, покрыт через 115 |
| 115 | Authentication Bypass | **SELECTED** | — | Обход MFA через reset flow |
| 122 | Privilege Abuse | **SELECTED** | — | Покрыт через 180, 1 |
| 125 | Flooding | NOT_APPLICABLE | OS/INFRA | DDoS на уровне сети/сервера |
| 130 | Excessive Allocation | NOT_APPLICABLE | OS/INFRA | Ресурсное исчерпание сервера |
| 131 | Resource Leak Exposure | NOT_APPLICABLE | CODE | Утечка ресурсов в коде |
| 148 | Content Spoofing | NOT_APPLICABLE | NOT_IAM | Подмена контента (XSS-подобное), Keycloak themes фиксированы |
| 163 | Spear Phishing | NOT_APPLICABLE | NO_CONFIG | Социальная инженерия, не конфигурация |
| 165 | File Manipulation | NOT_APPLICABLE | OS/INFRA | Манипуляция файлами на сервере |
| 169 | Footprinting | **SELECTED** | — | Покрыт через 541 (fingerprinting) |
| 206 | Signing Malicious Code | NOT_APPLICABLE | SUPPLY_CHAIN | Подписание вредоносного кода |
| 227 | Sustained Client Engagement | NOT_APPLICABLE | NOT_IAM | Удержание клиентского соединения |
| 233 | Privilege Escalation | **SELECTED** | — | Покрыт через 180 |
| 407 | Pretexting | NOT_APPLICABLE | NO_CONFIG | Социальная инженерия |
| 438 | Modification During Manufacture | NOT_APPLICABLE | SUPPLY_CHAIN | Hardware supply chain |
| 439 | Manipulation During Distribution | NOT_APPLICABLE | SUPPLY_CHAIN | Distribution tampering |
| 440 | Hardware Integrity Attack | NOT_APPLICABLE | PHYSICAL | Hardware |
| 558 | Replace Trusted Executable | NOT_APPLICABLE | OS/INFRA | Замена бинарников на сервере |

## Standard Attack Patterns (66)

| CAPEC | Название | Статус | Категория | Обоснование |
|-------|---------|--------|-----------|-------------|
| 1 | Accessing Functionality Not Constrained by ACLs | **SELECTED** | — | Неограниченные grant types |
| 2 | Inducing Account Lockout | **SELECTED** | — | Permanent lockout DoS |
| 17 | Using Malicious Files | NOT_APPLICABLE | NOT_IAM | File upload attacks, Keycloak не принимает файлы от пользователей |
| 19 | Embedding Scripts within Scripts | NOT_APPLICABLE | CODE | XSS через скрипты, код темы |
| 30 | Hijacking Privileged Thread | NOT_APPLICABLE | OS/INFRA | Thread hijacking на уровне ОС |
| 49 | Password Brute Forcing | **SELECTED** | — | Перебор паролей |
| 68 | Subvert Code-signing | NOT_APPLICABLE | SUPPLY_CHAIN | Подрыв подписи кода |
| 98 | Phishing | **SELECTED** | — | OAuth phishing через open redirect |
| 132 | Symlink Attack | NOT_APPLICABLE | OS/INFRA | Symlink на файловой системе |
| 141 | Cache Poisoning | NOT_APPLICABLE | OS/INFRA | DNS/HTTP cache poisoning на уровне инфраструктуры |
| 150 | Collect Data from Common Resources | NOT_APPLICABLE | OS/INFRA | Сбор данных из файлов/реестра |
| 158 | Sniffing Network Traffic | NOT_APPLICABLE | OS/INFRA | Сетевой сниффинг — покрыт косвенно через CAPEC-94 (AiTM) |
| 159 | Redirect Access to Libraries | NOT_APPLICABLE | OS/INFRA | DLL/library redirect |
| 177 | Create files with same name | NOT_APPLICABLE | OS/INFRA | File system attack |
| 180 | Exploiting Incorrect ACLs | **SELECTED** | — | Избыточные scopes/roles |
| 186 | Malicious Software Update | NOT_APPLICABLE | SUPPLY_CHAIN | Вредоносное обновление |
| 191 | Read Sensitive Constants | NOT_APPLICABLE | CODE | Реверс-инжиниринг бинарников |
| 196 | Session Credential Falsification | **SELECTED** | — | JWT forgery |
| 203 | Manipulate Registry | NOT_APPLICABLE | OS/INFRA | Windows registry |
| 251 | Local Code Inclusion | NOT_APPLICABLE | CODE | LFI/RFI |
| 267 | Leverage Alternate Encoding | NOT_APPLICABLE | CODE | Обход фильтров через encoding |
| 268 | Audit Log Manipulation | NOT_APPLICABLE | OS/INFRA | Манипуляция логами на сервере (наш V6.3.5 проверяет что логи включены, но не защиту от манипуляции) |
| 270 | Modification of Registry Run Keys | NOT_APPLICABLE | OS/INFRA | Windows registry persistence |
| 292 | Host Discovery | NOT_APPLICABLE | OS/INFRA | Сетевое сканирование |
| 295 | Timestamp Request | NOT_APPLICABLE | OS/INFRA | Разведка через timestamp |
| 300 | Port Scanning | NOT_APPLICABLE | OS/INFRA | Сетевое сканирование |
| 309 | Network Topology Mapping | NOT_APPLICABLE | OS/INFRA | Сетевая разведка |
| 312 | Active OS Fingerprinting | NOT_APPLICABLE | OS/INFRA | Определение ОС |
| 313 | Passive OS Fingerprinting | NOT_APPLICABLE | OS/INFRA | Определение ОС |
| 383 | Harvesting Info via API Events | NOT_APPLICABLE | NO_CONFIG | Мониторинг API — не misconfiguration |
| 442 | Infected Software | NOT_APPLICABLE | SUPPLY_CHAIN | Вредоносное ПО |
| 457 | USB Memory Attacks | NOT_APPLICABLE | PHYSICAL | USB атаки |
| 464 | Evercookie | NOT_APPLICABLE | NOT_IAM | Persistent tracking cookies |
| 465 | Transparent Proxy Abuse | NOT_APPLICABLE | OS/INFRA | Прокси-атаки — частично покрыто V4.1.3 (ProxyHeadersCheck) |
| 471 | Search Order Hijacking | NOT_APPLICABLE | OS/INFRA | DLL search order |
| 479 | Malicious Root Certificate | NOT_APPLICABLE | OS/INFRA | Установка вредоносного CA на клиенте |
| 480 | Escaping Virtualization | NOT_APPLICABLE | OS/INFRA | VM escape |
| 481 | Contradictory Traffic Routing | NOT_APPLICABLE | OS/INFRA | Сетевая маршрутизация |
| 485 | Signature Spoofing by Key Recreation | NOT_APPLICABLE | CODE | Пересоздание криптоключей — покрыто косвенно V11.2.3 (weak keys) |
| 488 | HTTP Flood | NOT_APPLICABLE | OS/INFRA | DDoS |
| 489 | SSL Flood | NOT_APPLICABLE | OS/INFRA | TLS DDoS |
| 490 | Amplification | NOT_APPLICABLE | OS/INFRA | DDoS amplification |
| 497 | File Discovery | NOT_APPLICABLE | OS/INFRA | Поиск файлов на сервере |
| 520 | Counterfeit Hardware During Assembly | NOT_APPLICABLE | PHYSICAL | Hardware |
| 522 | Malicious Hardware Replacement | NOT_APPLICABLE | PHYSICAL | Hardware |
| 523 | Malicious Software Implanted | NOT_APPLICABLE | SUPPLY_CHAIN | Software implant |
| 539 | ASIC With Malicious Functionality | NOT_APPLICABLE | PHYSICAL | Hardware |
| 541 | Application Fingerprinting | **SELECTED** | — | Определение версии Keycloak |
| 543 | Counterfeit Websites | NOT_APPLICABLE | NO_CONFIG | Фишинговые сайты — не конфигурация Keycloak |
| 552 | Install Rootkit | NOT_APPLICABLE | OS/INFRA | Rootkit на сервере |
| 568 | Capture Credentials via Keylogger | NOT_APPLICABLE | PHYSICAL | Keylogger на клиенте |
| 569 | Collect Data as Provided by Users | NOT_APPLICABLE | NO_CONFIG | Сбор данных от пользователей (фишинг) |
| 571 | Block Logging to Central Repository | NOT_APPLICABLE | OS/INFRA | Блокировка логирования на уровне сервера |
| 572 | Artificially Inflate File Sizes | NOT_APPLICABLE | OS/INFRA | Раздувание файлов |
| 573 | Process Footprinting | NOT_APPLICABLE | OS/INFRA | Разведка процессов на сервере |
| 574 | Services Footprinting | NOT_APPLICABLE | OS/INFRA | Разведка сервисов |
| 575 | Account Footprinting | NOT_APPLICABLE | BUILT_IN | Keycloak не раскрывает существование аккаунтов (generic errors) |
| 576 | Group Permission Footprinting | NOT_APPLICABLE | OS/INFRA | Разведка групповых прав |
| 577 | Owner Footprinting | NOT_APPLICABLE | OS/INFRA | Разведка владельцев |
| 579 | Replace Winlogon Helper DLL | NOT_APPLICABLE | OS/INFRA | Windows persistence |
| 581 | Security Software Footprinting | NOT_APPLICABLE | OS/INFRA | Разведка ПО безопасности |
| 593 | Session Hijacking | **SELECTED** | — | Перехват сессии |
| 609 | Cellular Traffic Intercept | NOT_APPLICABLE | PHYSICAL | Перехват сотовой связи |
| 616 | Establish Rogue Location | NOT_APPLICABLE | PHYSICAL | Поддельная базовая станция |
| 634 | Probe Audio/Video Peripherals | NOT_APPLICABLE | PHYSICAL | Разведка периферии |
| 635 | Deceptive Filenames | NOT_APPLICABLE | OS/INFRA | Обманчивые имена файлов |
| 645 | Pass The Ticket | NOT_APPLICABLE | NOT_IAM | Kerberos ticket reuse — Keycloak не использует Kerberos tickets для основной аутентификации |
| 650 | Upload Web Shell | NOT_APPLICABLE | NOT_IAM | Web shell — Keycloak не принимает file uploads |

## Detailed Attack Patterns (65)

| CAPEC | Название | Статус | Категория | Обоснование |
|-------|---------|--------|-----------|-------------|
| 11 | Cause Web Server Misclassification | NOT_APPLICABLE | CODE | Content-Type manipulation — покрыто V4.1.1 |
| 13 | Subverting Environment Variables | NOT_APPLICABLE | OS/INFRA | Переменные окружения сервера |
| 31 | Accessing/Modifying HTTP Cookies | **SELECTED** | — | Cookie theft |
| 35 | Executable Code in Non-Executable Files | NOT_APPLICABLE | CODE | Исполняемый код в файлах |
| 37 | Retrieve Embedded Sensitive Data | NOT_APPLICABLE | CODE | Sensitive data в бинарниках |
| 38 | Config File Search Paths | NOT_APPLICABLE | OS/INFRA | Манипуляция путями конфигов |
| 55 | Rainbow Table Password Cracking | **SELECTED** | — | Офлайн перебор хешей |
| 57 | REST Trust Exploitation | NOT_APPLICABLE | BUILT_IN | REST API trust — Keycloak использует стандартные OAuth/OIDC endpoints |
| 60 | Reusing Session IDs | **SELECTED** | — | Session replay |
| 65 | Sniff Application Code | NOT_APPLICABLE | OS/INFRA | Перехват кода приложения |
| 70 | Default Usernames/Passwords | **SELECTED** | — | Стандартные credentials |
| 127 | Directory Indexing | NOT_APPLICABLE | NOT_IAM | Листинг директорий — Keycloak не экспонирует |
| 142 | DNS Cache Poisoning | NOT_APPLICABLE | OS/INFRA | DNS poisoning |
| 163 | Spear Phishing | NOT_APPLICABLE | NO_CONFIG | Социальная инженерия |
| 187 | Malicious Update via Redirection | NOT_APPLICABLE | SUPPLY_CHAIN | Перенаправление обновлений |
| 204 | Lifting Sensitive Data from Cache | **SELECTED** | — | Данные из кеша браузера |
| 443 | Malicious Logic by Developer | NOT_APPLICABLE | SUPPLY_CHAIN | Insider threat |
| 445 | Malicious Logic via Config Mgmt | NOT_APPLICABLE | SUPPLY_CHAIN | Config management compromise |
| 446 | Malicious Logic via 3rd Party | NOT_APPLICABLE | SUPPLY_CHAIN | Third-party compromise |
| 448 | Embed Virus into DLL | NOT_APPLICABLE | CODE | DLL virus |
| 469 | HTTP DoS | NOT_APPLICABLE | OS/INFRA | HTTP DDoS |
| 473 | Signature Spoof | NOT_APPLICABLE | CODE | Общий signature spoofing — покрыт через CAPEC-196 |
| 474 | Signature Spoofing by Key Theft | NOT_APPLICABLE | OS/INFRA | Кража ключей с сервера |
| 478 | Windows Service Config | NOT_APPLICABLE | OS/INFRA | Windows services |
| 482 | TCP Flood | NOT_APPLICABLE | OS/INFRA | TCP DDoS |
| 504 | Task Impersonation | NOT_APPLICABLE | OS/INFRA | Имперсонация задач ОС |
| 509 | Kerberoasting | NOT_APPLICABLE | NOT_IAM | Kerberos-специфичная атака |
| 511 | Infiltrate Dev Environment | NOT_APPLICABLE | SUPPLY_CHAIN | Compromise development |
| 516 | Hardware Substitution | NOT_APPLICABLE | PHYSICAL | Hardware |
| 528 | XML Flood | NOT_APPLICABLE | OS/INFRA | XML DDoS |
| 531 | Hardware Substitution | NOT_APPLICABLE | PHYSICAL | Hardware |
| 532 | Altered BIOS | NOT_APPLICABLE | PHYSICAL | BIOS manipulation |
| 537 | Infiltrate HW Dev Environment | NOT_APPLICABLE | PHYSICAL | Hardware development |
| 538 | Open-Source Library Manipulation | NOT_APPLICABLE | SUPPLY_CHAIN | OSS compromise |
| 542 | Targeted Malware | NOT_APPLICABLE | CODE | Malware |
| 545 | Pull Data from System Resources | NOT_APPLICABLE | OS/INFRA | Сбор системных данных |
| 550 | Install New Service | NOT_APPLICABLE | OS/INFRA | Установка сервиса |
| 551 | Modify Existing Service | NOT_APPLICABLE | OS/INFRA | Модификация сервиса |
| 555 | Remote Services with Stolen Creds | NOT_APPLICABLE | NO_CONFIG | Использование украденных credentials — не misconfiguration, а post-exploitation |
| 556 | Replace File Extension Handlers | NOT_APPLICABLE | OS/INFRA | File handlers |
| 560 | Use of Known Domain Credentials | NOT_APPLICABLE | NO_CONFIG | Аналогично 555 — post-exploitation |
| 561 | Windows Admin Shares | NOT_APPLICABLE | OS/INFRA | Windows shares |
| 562 | Modify Shared File | NOT_APPLICABLE | OS/INFRA | File manipulation |
| 564 | Run Software at Logon | NOT_APPLICABLE | OS/INFRA | Persistence через logon |
| 565 | Password Spraying | **SELECTED** | — | Spraying по аккаунтам |
| 578 | Disable Security Software | NOT_APPLICABLE | OS/INFRA | Отключение антивируса |
| 580 | System Footprinting | NOT_APPLICABLE | OS/INFRA | Системная разведка |
| 600 | Credential Stuffing | **SELECTED** | — | Stuffing утёкших credentials |
| 620 | Drop Encryption Level | **SELECTED** | — | TLS downgrade |
| 633 | Token Impersonation | **SELECTED** | — | Cross-service token abuse |
| 636 | Hiding Data in Files | NOT_APPLICABLE | CODE | Steganography |
| 637 | Collect Data from Clipboard | NOT_APPLICABLE | PHYSICAL | Clipboard sniffing |
| 638 | Altered Component Firmware | NOT_APPLICABLE | PHYSICAL | Firmware |
| 639 | Probe System Files | NOT_APPLICABLE | OS/INFRA | File system probing |
| 640 | Code Inclusion in Process | NOT_APPLICABLE | OS/INFRA | Process injection |
| 641 | DLL Side-Loading | NOT_APPLICABLE | OS/INFRA | DLL attack |
| 642 | Replace Binaries | NOT_APPLICABLE | OS/INFRA | Binary replacement |
| 643 | Identify Shared Dirs | NOT_APPLICABLE | OS/INFRA | File system recon |
| 644 | Pass The Hash | NOT_APPLICABLE | NOT_IAM | NTLM hash reuse |
| 646 | Peripheral Footprinting | NOT_APPLICABLE | PHYSICAL | Device recon |
| 647 | Collect Data from Registries | NOT_APPLICABLE | OS/INFRA | Registry data |
| 648 | Screen Capture | NOT_APPLICABLE | PHYSICAL | Keylogger/screen capture |
| 649 | Space in File Extension | NOT_APPLICABLE | OS/INFRA | File extension trick |

---

## Итого

| Категория исключения | Количество |
|---------------------|-----------|
| **SELECTED** (релевантные) | **20** |
| OS/INFRA (операционная система, сеть) | 73 |
| CODE (исходный код, бинарники) | 12 |
| SUPPLY_CHAIN (цепочка поставок) | 13 |
| PHYSICAL (физический доступ) | 14 |
| NOT_IAM (не IAM/OAuth/OIDC) | 10 |
| BUILT_IN (Keycloak защищён встроенно) | 2 |
| NO_CONFIG (нельзя обнаружить через конфиг) | 9 |

**Всего в CAPEC-658:** 153 уникальных паттерна
**Отобрано:** 20 (13%)
**Отсеяно:** 133 (87%) — с указанием конкретной причины для каждого
