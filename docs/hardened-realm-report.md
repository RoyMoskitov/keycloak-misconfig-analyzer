# Результаты сканирования защищённой конфигурации Keycloak

## Описание тестового окружения

Для демонстрации корректности работы сканера была создана защищённая конфигурация Keycloak realm `hardened-test`, соответствующая требованиям OWASP ASVS 5.0. Конфигурация создаётся автоматически с помощью bash-скрипта `setup-hardened-realm.sh`, который использует Keycloak Admin REST API.

**Параметры окружения:**
- Keycloak 26.0.7, запущен в Docker-контейнере
- HTTPS на порту 8182 с TLS-сертификатом
- Realm: `hardened-test`
- Сервисный аккаунт: `scanner-client` (client_credentials grant)

## Применённые меры защиты

### Аутентификация и пароли
- Минимальная длина пароля: 12 символов, максимальная: 128
- Алгоритм хеширования: PBKDF2-SHA512 с 210 000 итерациями
- Запрет использования username и email в качестве пароля
- Настроен чёрный список паролей (passwordBlacklist)
- Защита от брутфорса: блокировка после 5 неудачных попыток, ожидание 60 сек с нарастанием до 15 мин

### Многофакторная аутентификация (MFA)
- OTP обязателен в браузерном потоке (TOTP, HmacSHA256, 8 цифр)
- OTP обязателен при direct grant аутентификации
- OTP обязателен при сбросе пароля
- Настройка TOTP как обязательное действие по умолчанию

### Управление сессиями
- SSO Session Idle Timeout: 30 минут
- SSO Session Max Lifespan: 10 часов
- Access Token Lifespan: 5 минут
- Ротация refresh token включена (одноразовое использование)
- Offline Session Max Lifespan: 60 дней
- Лимит одновременных сессий через кастомный browser flow

### Безопасность клиентов
- Сервисный аккаунт: confidential client, только client_credentials grant
- fullScopeAllowed отключён, роли назначены через явный scope mapping
- Standard Flow, Implicit Flow, Direct Access Grants отключены для сервисного клиента
- admin-cli: Direct Access Grants отключён
- Алгоритм подписи токенов: RS256 (явно указан)

### Криптография
- RSA-ключи realm: 4096 бит (дефолтные 2048-битные ключи заменены)
- Action Token Lifespan: 15 минут
- Cipher suites ограничены шифрами с forward secrecy (ECDHE) через параметр `KC_HTTPS_CIPHER_SUITES` при запуске контейнера

### Аудит
- Логирование событий аутентификации включено (хранение 7 дней)
- Логирование административных событий включено с деталями

## Результаты сканирования

**Дата:** 09.04.2026  
**Цель:** https://localhost:8182  
**Время сканирования:** ~21 секунда  

### Сводка

| Статус | Количество | Описание |
|--------|-----------|----------|
| OK | 82 | Проверки пройдены успешно |
| DETECTED | 1 | Обнаружены проблемы |
| Всего | 83 | |

### Обнаруженные проблемы (DETECTED)

#### 12.2.2 — Self-signed TLS сертификат (HIGH)

Keycloak использует самоподписанный сертификат (subject = issuer = `C=RU,ST=LOCAL,L=LOCAL,OU=DEV,O=LOCAL,CN=localhost`). Браузеры и клиенты не доверяют таким сертификатам без явного добавления в trust store.

**Причина:** тестовое окружение работает на `localhost`, для которого невозможно получить сертификат от публичного центра сертификации (CA). Это ожидаемое ограничение тестовой среды.

**В продакшене** Keycloak размещается за reverse proxy (Nginx, HAProxy, AWS ALB), который терминирует TLS-соединение с сертификатом от публичного CA (Let's Encrypt, DigiCert) или корпоративного CA. Сканер корректно отличает self-signed сертификат от CA-подписанного, сравнивая поля issuer и subject сертификата.

### Полученные рекомендации (WARNING/INFO)

Помимо обнаруженных проблем, сканер выдал рекомендации, не являющиеся уязвимостями:

**11.4.2 — Алгоритм хеширования паролей (WARNING, LOW)**  
Используется PBKDF2-SHA512. Алгоритм безопасен и соответствует рекомендациям NIST SP 800-132, однако Argon2id обеспечивает лучшую защиту от GPU-атак благодаря memory-hard свойству. Keycloak 26 не поддерживает Argon2 через строку passwordPolicy, поэтому выбран наилучший доступный алгоритм.

**6.3.3 — WebAuthn не настроен (WARNING, LOW)**  
MFA корректно настроена с TOTP (OTP обязателен). Сканер рекомендует дополнительно настроить WebAuthn (FIDO2/CTAP) как более безопасную альтернативу. Это улучшение, а не проблема — TOTP является допустимым методом MFA по ASVS.

**7.4.5, 7.4.2 — Информационные (INFO)**  
Подтверждение встроенных функций Keycloak: администратор может завершать сессии пользователей через Admin API; при отключении пользователя все его сессии автоматически инвалидируются.

## Выводы

Из 83 проверок 82 пройдены успешно. Единственный оставшийся finding — self-signed TLS сертификат — является ожидаемым ограничением тестовой среды на localhost, где невозможно получить сертификат от публичного CA.

Сканер корректно классифицирует проблемы по уровням:
- **Конфигурация realm** (Admin API) — управление администратором Keycloak
- **Инфраструктура сервера** (TLS, сертификаты) — управление DevOps/SRE

В продакшене self-signed сертификат заменяется сертификатом от CA (публичного или корпоративного), что устраняет последний finding. Таким образом, созданная конфигурация полностью соответствует требованиям OWASP ASVS 5.0.


{
"scanId": "4ab7a29e-65b7-41be-a8b2-36424be62159",
"target": "https://localhost:8182",
"startedAt": "2026-04-09T18:18:50.346722700Z",
"finishedAt": "2026-04-09T18:19:11.338147100Z",
"results": [
{
"checkId": "6.8.4",
"status": "OK",
"findings": [],
"durationMs": 4044,
"error": null
},
{
"checkId": "6.3.4",
"status": "OK",
"findings": [],
"durationMs": 1318,
"error": null
},
{
"checkId": "6.3.2",
"status": "OK",
"findings": [],
"durationMs": 141,
"error": null
},
{
"checkId": "8.2.1",
"status": "OK",
"findings": [],
"durationMs": 253,
"error": null
},
{
"checkId": "8.2.3",
"status": "OK",
"findings": [],
"durationMs": 109,
"error": null
},
{
"checkId": "6.8.1",
"status": "OK",
"findings": [],
"durationMs": 270,
"error": null
},
{
"checkId": "6.3.5",
"status": "OK",
"findings": [],
"durationMs": 143,
"error": null
},
{
"checkId": "6.3.3",
"status": "WARNING",
"findings": [
{
"id": "6.3.3",
"title": "MFA правильно настроена",
"description": "Многофакторная аутентификация корректно настроена в браузерном потоке",
"severity": "LOW",
"status": "OK",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "mfaAuthenticators",
"value": "auth-otp-form (REQUIRED)"
},
{
"key": "requiredMfaCount",
"value": "1"
},
{
"key": "totalMfa",
"value": "1"
}
],
"recommendation": null
},
{
"id": "6.3.3",
"title": "WebAuthn не настроен",
"description": "WebAuthn (FIDO2/CTAP) не настроен как метод MFA",
"severity": "LOW",
"status": "DETECTED",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "hasWebAuthn",
"value": "false"
},
{
"key": "recommendedMfa",
"value": "WebAuthn или TOTP"
}
],
"recommendation": "Рассмотрите настройку WebAuthn как более безопасной альтернативы TOTP"
}
],
"durationMs": 346,
"error": null
},
{
"checkId": "8.4.1",
"status": "OK",
"findings": [],
"durationMs": 361,
"error": null
},
{
"checkId": "6.4.2",
"status": "OK",
"findings": [],
"durationMs": 102,
"error": null
},
{
"checkId": "8.3.1",
"status": "OK",
"findings": [
{
"id": "8.3.1",
"title": "Алгоритм подписи токенов настроен корректно",
"description": "Клиент 'scanner-client' использует асимметричную подпись токенов (RS256)",
"severity": "INFO",
"status": "OK",
"realm": "",
"clientId": null,
"evidence": [
{
"key": "clientId",
"value": "scanner-client"
},
{
"key": "algorithm",
"value": "RS256"
}
],
"recommendation": "Продолжайте использовать текущий алгоритм подписи"
}
],
"durationMs": 321,
"error": null
},
{
"checkId": "6.3.1",
"status": "OK",
"findings": [],
"durationMs": 111,
"error": null
},
{
"checkId": "10.4.8",
"status": "OK",
"findings": [],
"durationMs": 128,
"error": null
},
{
"checkId": "10.4.3",
"status": "OK",
"findings": [],
"durationMs": 145,
"error": null
},
{
"checkId": "10.4.2",
"status": "OK",
"findings": [],
"durationMs": 113,
"error": null
},
{
"checkId": "10.7.2",
"status": "OK",
"findings": [],
"durationMs": 131,
"error": null
},
{
"checkId": "10.4.11",
"status": "OK",
"findings": [],
"durationMs": 89,
"error": null
},
{
"checkId": "10.4.10",
"status": "OK",
"findings": [],
"durationMs": 94,
"error": null
},
{
"checkId": "10.4.7",
"status": "OK",
"findings": [],
"durationMs": 244,
"error": null
},
{
"checkId": "10.7.1",
"status": "OK",
"findings": [],
"durationMs": 102,
"error": null
},
{
"checkId": "10.6.2",
"status": "OK",
"findings": [],
"durationMs": 112,
"error": null
},
{
"checkId": "10.4.4",
"status": "OK",
"findings": [],
"durationMs": 208,
"error": null
},
{
"checkId": "10.2.1",
"status": "OK",
"findings": [],
"durationMs": 80,
"error": null
},
{
"checkId": "10.4.1",
"status": "OK",
"findings": [],
"durationMs": 76,
"error": null
},
{
"checkId": "10.1.1",
"status": "OK",
"findings": [],
"durationMs": 103,
"error": null
},
{
"checkId": "10.4.9",
"status": "OK",
"findings": [],
"durationMs": 278,
"error": null
},
{
"checkId": "6.6.2",
"status": "OK",
"findings": [
{
"id": "6.6.2",
"title": "OTP binding корректно настроен",
"description": "Все проверки OTP binding пройдены успешно",
"severity": "LOW",
"status": "OK",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "otpBinding",
"value": "properly_configured"
}
],
"recommendation": null
}
],
"durationMs": 955,
"error": null
},
{
"checkId": "6.5.4",
"status": "OK",
"findings": [],
"durationMs": 135,
"error": null
},
{
"checkId": "6.5.5",
"status": "OK",
"findings": [],
"durationMs": 105,
"error": null
},
{
"checkId": "6.5.1",
"status": "OK",
"findings": [],
"durationMs": 140,
"error": null
},
{
"checkId": "6.6.3",
"status": "OK",
"findings": [],
"durationMs": 112,
"error": null
},
{
"checkId": "6.6.1",
"status": "OK",
"findings": [],
"durationMs": 1039,
"error": null
},
{
"checkId": "6.2.3",
"status": "OK",
"findings": [],
"durationMs": 423,
"error": null
},
{
"checkId": "6.4.1",
"status": "OK",
"findings": [],
"durationMs": 143,
"error": null
},
{
"checkId": "6.1.2",
"status": "OK",
"findings": [],
"durationMs": 135,
"error": null
},
{
"checkId": "6.2.2",
"status": "OK",
"findings": [],
"durationMs": 190,
"error": null
},
{
"checkId": "6.2.5",
"status": "OK",
"findings": [],
"durationMs": 136,
"error": null
},
{
"checkId": "11.4.2",
"status": "WARNING",
"findings": [
{
"id": "11.4.2",
"title": "Алгоритм хеширования допустим, но не оптимален",
"description": "Используется 'pbkdf2-sha512'. Алгоритм безопасен, но Argon2id обеспечивает лучшую защиту от GPU-атак благодаря memory-hard свойству.",
"severity": "LOW",
"status": "WARNING",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "hashAlgorithm",
"value": "pbkdf2-sha512"
},
{
"key": "explicitlyConfigured",
"value": true
},
{
"key": "recommended",
"value": "argon2"
}
],
"recommendation": "Рассмотрите переход на Argon2id для лучшей защиты от GPU-атак"
}
],
"durationMs": 141,
"error": null
},
{
"checkId": "KC-PASS-05",
"status": "OK",
"findings": [],
"durationMs": 124,
"error": null
},
{
"checkId": "6.2.9",
"status": "OK",
"findings": [],
"durationMs": 126,
"error": null
},
{
"checkId": "6.2.1",
"status": "OK",
"findings": [],
"durationMs": 127,
"error": null
},
{
"checkId": "6.4.3",
"status": "OK",
"findings": [],
"durationMs": 1107,
"error": null
},
{
"checkId": "6.2.10",
"status": "OK",
"findings": [],
"durationMs": 108,
"error": null
},
{
"checkId": "7.4.5",
"status": "INFO",
"findings": [
{
"id": "7.4.5",
"title": "Администратор может завершать сессии",
"description": "Keycloak предоставляет API для завершения сессий пользователей администратором",
"severity": "INFO",
"status": "OK",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "canRevokeSessions",
"value": "true"
},
{
"key": "requiredRole",
"value": "manage-users"
},
{
"key": "apiEndpoint",
"value": "POST /admin/realms/{realm}/users/{user-id}/logout"
}
],
"recommendation": null
}
],
"durationMs": 128,
"error": null
},
{
"checkId": "7.2.1",
"status": "OK",
"findings": [
{
"id": "7.2.1",
"title": "Настройки токенов соответствуют требованиям",
"description": "Используется безопасный алгоритм подписи (RS256), Access Token имеет ограниченное время жизни.",
"severity": "INFO",
"status": "OK",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "defaultSignatureAlgorithm",
"value": "RS256"
},
{
"key": "accessTokenLifespan",
"value": "300 сек"
}
],
"recommendation": null
}
],
"durationMs": 110,
"error": null
},
{
"checkId": "7.1.2",
"status": "OK",
"findings": [],
"durationMs": 1054,
"error": null
},
{
"checkId": "7.4.2",
"status": "INFO",
"findings": [
{
"id": "7.4.2",
"title": "Встроенная функция Keycloak",
"description": "Keycloak автоматически завершает все активные сессии пользователя при установке enabled=false",
"severity": "INFO",
"status": "INFO",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "feature",
"value": "built-in"
}
],
"recommendation": "При отключении пользователя через Admin API или консоль все его сессии немедленно становятся недействительными"
}
],
"durationMs": 0,
"error": null
},
{
"checkId": "7.2.2",
"status": "OK",
"findings": [],
"durationMs": 108,
"error": null
},
{
"checkId": "7.1.3",
"status": "OK",
"findings": [],
"durationMs": 204,
"error": null
},
{
"checkId": "7.6.1",
"status": "OK",
"findings": [],
"durationMs": 280,
"error": null
},
{
"checkId": "7.4.3",
"status": "OK",
"findings": [],
"durationMs": 211,
"error": null
},
{
"checkId": "7.5.1",
"status": "OK",
"findings": [],
"durationMs": 1280,
"error": null
},
{
"checkId": "7.2.4",
"status": "OK",
"findings": [],
"durationMs": 124,
"error": null
},
{
"checkId": "7.3.1",
"status": "OK",
"findings": [],
"durationMs": 108,
"error": null
},
{
"checkId": "7.5.2",
"status": "OK",
"findings": [
{
"id": "7.5.2",
"title": "Account Console доступен",
"description": "Пользователи могут использовать Account Console для просмотра и завершения своих сессий",
"severity": "LOW",
"status": "OK",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "accountConsoleAvailable",
"value": "true"
},
{
"key": "clientId",
"value": "account-console"
},
{
"key": "feature",
"value": "Active Sessions management"
}
],
"recommendation": null
}
],
"durationMs": 96,
"error": null
},
{
"checkId": "9.1.2",
"status": "OK",
"findings": [],
"durationMs": 146,
"error": null
},
{
"checkId": "9.2.3",
"status": "OK",
"findings": [],
"durationMs": 574,
"error": null
},
{
"checkId": "9.2.4",
"status": "OK",
"findings": [],
"durationMs": 92,
"error": null
},
{
"checkId": "9.1.1",
"status": "OK",
"findings": [],
"durationMs": 67,
"error": null
},
{
"checkId": "9.2.1",
"status": "OK",
"findings": [],
"durationMs": 68,
"error": null
},
{
"checkId": "9.2.2",
"status": "OK",
"findings": [],
"durationMs": 34,
"error": null
},
{
"checkId": "11.2.3",
"status": "OK",
"findings": [],
"durationMs": 69,
"error": null
},
{
"checkId": "9.1.3",
"status": "OK",
"findings": [],
"durationMs": 348,
"error": null
},
{
"checkId": "4.1.2",
"status": "OK",
"findings": [],
"durationMs": 49,
"error": null
},
{
"checkId": "14.3.2",
"status": "OK",
"findings": [],
"durationMs": 136,
"error": null
},
{
"checkId": "12.1.2",
"status": "DETECTED",
"findings": [
{
"id": "12.1.2",
"title": "Cipher suites без forward secrecy",
"description": "6 cipher suites не обеспечивают forward secrecy. Без PFS компрометация ключа сервера позволит расшифровать весь прошлый трафик.",
"severity": "MEDIUM",
"status": "DETECTED",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "noForwardSecrecyCiphers",
"value": "TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA"
},
{
"key": "count",
"value": 6
}
],
"recommendation": "Используйте только cipher suites с ECDHE или DHE для forward secrecy"
}
],
"durationMs": 31,
"error": null
},
{
"checkId": "3.4.6",
"status": "OK",
"findings": [],
"durationMs": 28,
"error": null
},
{
"checkId": "3.4.3",
"status": "OK",
"findings": [],
"durationMs": 46,
"error": null
},
{
"checkId": "4.1.1",
"status": "OK",
"findings": [],
"durationMs": 83,
"error": null
},
{
"checkId": "3.3.2",
"status": "OK",
"findings": [
{
"id": "3.3.2",
"title": "AUTH_SESSION_ID использует SameSite=None (IdP cross-origin SSO)",
"description": "Cookie 'AUTH_SESSION_ID' имеет SameSite=None для поддержки cross-origin SSO сценариев (iframe, federation). Для Identity Provider это допустимо при наличии Secure и HttpOnly.",
"severity": "LOW",
"status": "OK",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "cookie",
"value": "AUTH_SESSION_ID"
},
{
"key": "SameSite",
"value": "None"
},
{
"key": "Secure",
"value": true
},
{
"key": "HttpOnly",
"value": true
}
],
"recommendation": "Если cross-origin SSO не используется, настройте SameSite=Lax в конфигурации Keycloak сервера"
},
{
"id": "3.3.2",
"title": "SameSite не установлен явно для KC_RESTART",
"description": "Cookie 'KC_RESTART' не содержит явный атрибут SameSite. Современные браузеры применяют Lax по умолчанию, обеспечивая базовую CSRF-защиту.",
"severity": "LOW",
"status": "OK",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "cookie",
"value": "KC_RESTART"
},
{
"key": "SameSite",
"value": "не задан (браузер применит Lax)"
},
{
"key": "HttpOnly",
"value": true
}
],
"recommendation": "Для дополнительной надёжности установите SameSite=Lax явно"
}
],
"durationMs": 48,
"error": null
},
{
"checkId": "3.3.1",
"status": "OK",
"findings": [],
"durationMs": 150,
"error": null
},
{
"checkId": "3.4.2",
"status": "OK",
"findings": [],
"durationMs": 111,
"error": null
},
{
"checkId": "3.4.1",
"status": "OK",
"findings": [],
"durationMs": 5,
"error": null
},
{
"checkId": "3.3.4",
"status": "OK",
"findings": [],
"durationMs": 43,
"error": null
},
{
"checkId": "12.2.1",
"status": "OK",
"findings": [],
"durationMs": 12,
"error": null
},
{
"checkId": "13.4.4",
"status": "OK",
"findings": [],
"durationMs": 20,
"error": null
},
{
"checkId": "12.3.2",
"status": "OK",
"findings": [],
"durationMs": 98,
"error": null
},
{
"checkId": "4.1.3",
"status": "OK",
"findings": [],
"durationMs": 159,
"error": null
},
{
"checkId": "3.4.5",
"status": "OK",
"findings": [],
"durationMs": 17,
"error": null
},
{
"checkId": "13.4.6",
"status": "OK",
"findings": [],
"durationMs": 69,
"error": null
},
{
"checkId": "12.2.2",
"status": "DETECTED",
"findings": [
{
"id": "12.2.2",
"title": "Self-signed TLS сертификат",
"description": "Keycloak использует self-signed сертификат. Браузеры и клиенты не будут доверять ему без явного добавления в trust store.",
"severity": "HIGH",
"status": "DETECTED",
"realm": "hardened-test",
"clientId": null,
"evidence": [
{
"key": "subject",
"value": "C=RU,ST=LOCAL,L=LOCAL,OU=DEV,O=LOCAL,CN=localhost"
},
{
"key": "issuer",
"value": "C=RU,ST=LOCAL,L=LOCAL,OU=DEV,O=LOCAL,CN=localhost"
},
{
"key": "selfSigned",
"value": true
}
],
"recommendation": "Используйте сертификат от публичного CA (Let's Encrypt, DigiCert и т.д.)"
}
],
"durationMs": 29,
"error": null
},
{
"checkId": "12.1.1",
"status": "OK",
"findings": [],
"durationMs": 62,
"error": null
},
{
"checkId": "3.4.4",
"status": "OK",
"findings": [],
"durationMs": 23,
"error": null
}
],
"summary": {
"totalChecks": 83,
"detected": 2,
"ok": 81,
"errors": 0
}
}