# Результаты сканирования уязвимой конфигурации Keycloak

## Описание тестового окружения

Для демонстрации возможностей сканера была создана максимально уязвимая конфигурация Keycloak realm `vulnerable-test`, намеренно нарушающая требования OWASP ASVS 5.0. Конфигурация создается автоматически с помощью bash-скрипта `setup-vulnerable-realm.sh`, с дополнительными ручными изменениями через Admin Console.

**Параметры окружения:**
- Keycloak 24.0.3, запущен в Docker-контейнере
- HTTP на порту 8180 (без TLS)
- Health/Metrics endpoints включены (`KC_HEALTH_ENABLED=true`, `KC_METRICS_ENABLED=true`)
- Proxy headers доверяются (`KC_PROXY_HEADERS=xforwarded`)
- Realm: `vulnerable-test`
- Аутентификация сканера: `admin/adminpass` через master realm

## Применённые уязвимые настройки

### Аутентификация и пароли
- Минимальная длина пароля: 4 символа (ASVS требует не менее 8)
- Максимальная длина пароля: 20 символов (ASVS требует не менее 64)
- Жёсткие композиционные правила (uppercase + lowercase + digits + specialChars)
- Принудительная ротация паролей каждые 30 дней (NIST SP 800-63B запрещает)
- Нет черного списка паролей (passwordBlacklist отсутствует)
- Алгоритм хеширования: pbkdf2-sha256 с 27 500 итерациями (рекомендуется не менее 600 000)
- Стандартные аккаунты (admin, test, demo, guest, root) включены
- MFA отключена во всех flows (OTP Disabled через Admin Console)

### Управление сессиями
- SSO Session Idle Timeout: не задан (бесконечность)
- SSO Session Max Lifespan: не задан (бесконечность)
- Access Token Lifespan: 2 часа (рекомендуется не более 15 минут)
- Refresh token rotation отключена, max reuse = 10
- Offline session max lifespan не ограничен
- Remember Me: 30 дней
- Account Console отключена

### OAuth/OIDC клиенты
- 20+ bulk-клиентов с wildcard redirect URI (`*`)
- Implicit Flow и Direct Access Grants включены на всех клиентах
- PKCE не настроен ни на одном клиенте
- Consent не требуется для public клиентов
- fullScopeAllowed=true на всех клиентах
- offline_access в default scopes (вместо optional)
- Клиент `vulnerable-backend` с HS256 подписью и access token 24 часа
- Клиент `jwt-auth-client` с JWKS URL по HTTP

### Identity Providers
- 3 внешних IdP с trustEmail=true и без First Broker Login Flow
- Валидация подписей отключена для всех IdP
- Дублирование email запрещено (duplicateEmailsAllowed=false, что создает вектор user enumeration)

### Инфраструктура
- HTTP без TLS (sslRequired=none)
- Security headers удалены (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy)
- Health/Metrics endpoints публично доступны
- Proxy headers доверяются от любого источника
- Admin Console публично доступна

## Результаты сканирования

**Дата:** 12.04.2026
**Цель:** http://localhost:8180
**Realm:** vulnerable-test

### Сводка

| Статус | Количество | Описание |
|--------|-----------|----------|
| DETECTED | 78 | Обнаружены проблемы безопасности |
| WARNING | 1 | Допустимо, но не оптимально |
| OK | 5 | Проверка пройдена |
| Итого | 84 | |

### Детализация по категориям

#### Пароли (10 DETECTED, 1 WARNING)
| ASVS ID | Статус | Проблема |
|---------|--------|----------|
| 6.1.2 | DETECTED | Нет черного списка паролей |
| 6.2.1 | DETECTED | Минимальная длина 4 символа (менее 8) |
| 6.2.2 | DETECTED | Account Console отключена, UPDATE_PASSWORD disabled |
| 6.2.3 | DETECTED | Account Console недоступна для смены пароля |
| 6.2.5 | DETECTED | Жёсткие композиционные правила (digits + specialChars) |
| 6.2.9 | DETECTED | maxLength=20 (менее 64) |
| 6.2.10 | DETECTED | Принудительная ротация каждые 30 дней |
| 11.4.2 | WARNING | pbkdf2-sha256 допустим, Argon2id рекомендуется |
| KC-PASS-05 | DETECTED | 27 500 итераций (менее 600 000 для pbkdf2-sha256) |
| 11.2.3 | DETECTED | RSA ключи 2048 бит (менее рекомендуемых 3072) |
| 6.4.1 | DETECTED | Action tokens живут 24 часа, email не верифицируется |

#### Аутентификация (12 DETECTED)
| ASVS ID | Статус | Проблема |
|---------|--------|----------|
| 6.3.1 | DETECTED | Brute force protection отключена |
| 6.3.2 | DETECTED | Стандартные аккаунты (admin, test, demo, guest, root) включены |
| 6.3.3 | DETECTED | MFA не настроена |
| 6.3.4 | DETECTED | MFA только в CONDITIONAL sub-flow |
| 6.3.5 | DETECTED | Login Events и Admin Events отключены |
| 6.3.6 | DETECTED | Регистрация без CAPTCHA и без email verification |
| 6.3.7 | DETECTED | Нет email event listener, SMTP не настроен |
| 6.3.8 | DETECTED | Перечисление пользователей через форму регистрации |
| 6.4.2 | DETECTED | CONFIGURE_TOTP required action удалена |
| 6.4.3 | DETECTED | Сброс пароля обходит MFA |
| 6.8.1 | DETECTED | 3 IdP с trustEmail=true, нет First Broker Login Flow |
| 6.8.4 | DETECTED | ACR/AMR claims не настроены |

#### OTP (5 DETECTED)
| ASVS ID | Статус | Проблема |
|---------|--------|----------|
| 6.5.1 | DETECTED | HOTP вместо TOTP, lookAheadWindow=10, HmacSHA1 |
| 6.5.4 | DETECTED | 4 цифры (13 бит энтропии, менее 20 бит) |
| 6.5.5 | DETECTED | Период 120 секунд (более 30) |
| 6.6.1 | DETECTED | Нет ни одного механизма MFA в flows |
| 6.6.3 | DETECTED | Brute force отключена, OTP не защищен от перебора |

#### Сессии (10 DETECTED)
| ASVS ID | Статус | Проблема |
|---------|--------|----------|
| 7.1.2 | DETECTED | Нет лимита параллельных сессий |
| 7.2.1 | DETECTED | Access token 2 часа |
| 7.2.2 | DETECTED | Service account со статическим секретом |
| 7.2.4 | DETECTED | Refresh token rotation отключена, maxReuse=10 |
| 7.3.1 | DETECTED | Нет inactivity timeout, нет absolute lifetime, Remember Me 30 дней |
| 7.4.3 | DETECTED | revokeRefreshToken отключен, access token 2 часа |
| 7.5.1 | DETECTED | Account Console отключена, UPDATE_PASSWORD и CONFIGURE_TOTP disabled |
| 7.5.2 | DETECTED | Account Console отключена |
| 7.4.2 | OK | Встроенная функция KC (disable user = terminate sessions) |
| 7.4.5 | OK | Встроенная функция KC (admin session termination API) |

#### OAuth/OIDC (16 DETECTED)
| ASVS ID | Статус | Проблема |
|---------|--------|----------|
| 10.1.1 | DETECTED | Public clients с Direct Access Grants и refresh tokens |
| 10.2.1 | DETECTED | PKCE не настроен на 22+ клиентах |
| 10.4.1 | DETECTED | Wildcard redirect URIs, HTTP redirects |
| 10.4.3 | DETECTED | Access code lifespan 3600 сек (более 600), login lifespan 7200 сек |
| 10.4.4 | DETECTED | Implicit Flow + Direct Access Grants на всех клиентах |
| 10.4.7 | DETECTED | 27+ клиентов (подозрение на открытую dynamic registration) |
| 10.4.8 | DETECTED | Нет absolute expiration для refresh/offline tokens |
| 10.4.9 | DETECTED | revokeRefreshToken отключен, Account Console недоступна |
| 10.4.10 | DETECTED | Confidential клиенты используют client-secret (не private_key_jwt) |
| 10.4.11 | DETECTED | offline_access в default scopes |
| 10.6.2 | DETECTED | Frontchannel logout без валидации |
| 10.7.1 | DETECTED | 22+ public клиентов без consent |
| 10.7.2 | DETECTED | Consent screen без name/description |

#### Токены (10 DETECTED)
| ASVS ID | Статус | Проблема |
|---------|--------|----------|
| 8.2.1 | DETECTED | Default roles содержат привилегированные роли |
| 8.2.3 | DETECTED | Sensitive mappers (email, phone, address) в токенах public клиентов |
| 8.3.1 | DETECTED | Алгоритм подписи не задан для admin-cli |
| 8.4.1 | DETECTED | fullScopeAllowed=true на 25+ клиентах, 3+ корпоративных IdP в одном realm |
| 9.1.1 | DETECTED | Клиент с HS256 (симметричная подпись) |
| 9.1.2 | DETECTED | HS512 ключ в realm keys (не в allowlist) |
| 9.1.3 | DETECTED | JWKS URL по HTTP у jwt-auth-client |
| 9.2.1 | DETECTED | Per-client access token lifespan 86400 сек (24 часа) |
| 9.2.2 | DETECTED | Authorization claims в ID Token (token type confusion) |
| 9.2.3 | DETECTED | 3 клиента без audience mapper |
| 9.2.4 | DETECTED | Audience mapper не настроен |

#### Web/HTTP (15 DETECTED)
| ASVS ID | Статус | Проблема |
|---------|--------|----------|
| 3.3.1 | DETECTED | sslRequired=none |
| 3.3.2 | DETECTED | Cookies не получены для проверки SameSite |
| 3.4.1 | DETECTED | HSTS заголовок отсутствует |
| 3.4.2 | DETECTED | Wildcard в Web Origins |
| 3.4.3 | DETECTED | CSP заголовок отсутствует |
| 3.4.4 | DETECTED | X-Content-Type-Options отсутствует |
| 3.4.5 | DETECTED | Referrer-Policy=unsafe-url |
| 3.4.6 | DETECTED | X-Frame-Options отсутствует |
| 4.1.1 | DETECTED | Нет charset в Content-Type |
| 4.1.2 | DETECTED | OIDC Discovery содержит HTTP URLs |
| 4.1.3 | DETECTED | X-Forwarded-Host отражается в OIDC discovery |
| 12.1.1 | DETECTED | TLS не поддерживается |
| 12.1.2 | DETECTED | TLS не используется, cipher suites неприменимы |
| 12.2.1 | DETECTED | HTTP без TLS |
| 12.2.2 | DETECTED | TLS не используется, нет сертификата |
| 12.3.2 | DETECTED | IdP не валидируют подписи токенов |
| 13.4.5 | DETECTED | Health, Metrics endpoints публично доступны |
| 13.4.6 | DETECTED | Admin Console публично доступна |
| 14.3.2 | DETECTED | Нет Cache-Control: no-store на auth endpoint |

## Проверки со статусом OK: почему не обнаружены

### 3.3.4 -- HttpOnly на cookies
**ASVS:** "Cookie must have the HttpOnly attribute set"

Keycloak хардкодит HttpOnly на всех session cookies (AUTH_SESSION_ID, KC_RESTART, KEYCLOAK_IDENTITY) в исходном коде AuthenticationManager.java. Это не конфигурируется через Admin API или Admin Console. Единственное исключение -- cookie KEYCLOAK_SESSION намеренно без HttpOnly, так как OIDC Session Management iframe требует JavaScript доступ (подтверждено в GitHub Discussion #17116).

**Когда может быть DETECTED:** никогда на стандартном Keycloak. Теоретически при использовании кастомного SPI, модифицирующего cookie-атрибуты.

### 6.6.2 -- OTP Binding
**ASVS:** "Out-of-band authentication codes bound to the original authentication request"

Стандартный authenticator `auth-otp-form` в Keycloak не имеет настраиваемых config properties через Admin API. Параметры вроде allow.reuse или skip.binding не существуют в стандартной конфигурации KC. OTP binding обеспечивается на уровне исходного кода Keycloak и не может быть ослаблен через конфигурацию.

**Когда может быть DETECTED:** при установке стороннего OTP SPI (например keycloak-phone-provider), который может иметь собственные настройки binding.

### 13.4.4 -- HTTP TRACE
**ASVS:** "HTTP TRACE method not supported in production"

Keycloak работает на Quarkus/Vert.x, который маршрутизирует только явно зарегистрированные HTTP-методы. Метод TRACE не имеет обработчиков в Keycloak, Vert.x возвращает 405 Method Not Allowed.

**Когда может быть DETECTED:** никогда на стандартном Keycloak. При развертывании за reverse proxy (nginx, Apache), который может обрабатывать TRACE самостоятельно до передачи запроса в Keycloak.

### 7.4.2 -- Завершение сессий при отключении пользователя
**ASVS:** "Terminate all active sessions when user account is disabled"

Это встроенное поведение Keycloak -- при установке enabled=false все сессии пользователя немедленно инвалидируются. Нет конфигурации для отключения этого поведения.

**Когда может быть DETECTED:** никогда на стандартном Keycloak.

### 7.4.5 -- Завершение сессий администратором
**ASVS:** "Administrators able to terminate active sessions"

Keycloak предоставляет Admin REST API endpoint POST /admin/realms/{realm}/users/{user-id}/logout для завершения сессий. Требуется роль manage-users. Это встроенная возможность.

**Когда может быть DETECTED:** никогда на стандартном Keycloak.

## Проверка со статусом WARNING

### 11.4.2 -- Алгоритм хеширования паролей
**ASVS:** "Passwords stored using approved, computationally intensive KDF"

pbkdf2-sha256 является допустимым алгоритмом (есть в списке одобренных NIST), но Argon2id обеспечивает лучшую защиту от GPU-атак благодаря memory-hard свойству. WARNING означает "безопасно, но есть лучшая альтернатива".

**Когда может быть DETECTED:** при использовании устаревших или слабых алгоритмов (MD5, SHA-1), что невозможно в современных версиях Keycloak через стандартную конфигурацию.

## Сравнение с защищённой конфигурацией

| Метрика | vulnerable-test | hardened-test |
|---------|----------------|---------------|
| Всего проверок | 84 | 84 |
| DETECTED | 78 | ~6 |
| OK | 5 | ~73 |
| WARNING | 1 | ~3 |

Разница в 72+ обнаруженных проблемы демонстрирует способность сканера различать безопасную и небезопасную конфигурацию Keycloak.
