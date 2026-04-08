# Методика тестирования инструмента сканирования конфигурационной безопасности Keycloak

## 1. Цель тестирования

Верифицировать эффективность инструмента по трём аспектам:
1. **Точность обнаружения** — соответствие обнаруженных проблем реальным мисконфигурациям
2. **Полнота покрытия** — способность обнаружить все известные мисконфигурации
3. **Функциональная корректность** — работоспособность всех компонентов системы

## 2. Тестовое окружение

### 2.1 Инфраструктура

| Компонент | Версия | Описание |
|-----------|--------|----------|
| Keycloak | 26.0.7 | Quarkus-based, development mode |
| Docker | latest | Контейнеризация Keycloak |
| JDK | 21 | Среда выполнения сканера |
| Spring Boot | 3.5.6 | Фреймворк сканера |
| H2 Database | embedded | Хранение результатов |

### 2.2 Тестовые конфигурации

Для тестирования подготовлены 3 конфигурации Keycloak (realm):

**A) Default (master)** — стандартная конфигурация Keycloak "из коробки" без изменений.

**B) Vulnerable (vulnerable-test)** — намеренно небезопасная конфигурация, созданная скриптом `setup-vulnerable-realm.sh`:
- Brute force protection отключена
- Слабая парольная политика (min 4, max 20, composition rules)
- HOTP вместо TOTP, 4 цифры OTP
- Implicit flow и Direct Access Grants включены
- Wildcard redirect URIs и Web Origins
- Refresh token rotation отключена
- Session timeouts = 0 (бесконечные сессии)
- Account Console отключена
- Два IdP с trustEmail=true
- Default accounts (admin, test, demo, guest, root)
- Required Actions отключены

**C) Hardened (hardened-test)** — максимально безопасная конфигурация, созданная скриптом `setup-hardened-realm.sh`:
- Brute force protection с оптимальными параметрами
- Сильная парольная политика (min 12, blacklist)
- TOTP с HMAC-SHA256, 6 цифр
- Только Standard Flow с PKCE S256
- Exact-match HTTPS redirect URIs
- Refresh token rotation включена, maxReuse=0
- Session Idle=30min, Max=10h
- Events включены с 90-дневным хранением
- Consent required
- fullScopeAllowed=false

### 2.3 Воспроизводимость

```bash
# 1. Запуск Keycloak
cd test-environments
docker-compose up -d

# 2. Ожидание готовности (30 сек)
sleep 30

# 3. Создание тестовых realm
bash setup-vulnerable-realm.sh http://localhost:8180 admin adminpass
bash setup-hardened-realm.sh http://localhost:8180 admin adminpass

# 4. Запуск сканера
cd ..
./mvnw clean spring-boot:run
```

## 3. Эксперимент 1: Точность и полнота обнаружения

### 3.1 Методология

Для каждого тестового окружения:
1. Запустить скан через API
2. Сравнить результат с ground truth таблицей
3. Классифицировать каждый результат: TP, FP, TN, FN
4. Вычислить Precision, Recall, F1

### 3.2 Ground Truth

Ground truth определяется **до запуска скана** на основе анализа конфигурации:

| Категория | Vulnerable | Hardened | Default |
|-----------|:---:|:---:|:---:|
| **Ожидаемый DETECTED** | ~50 | ~5 | ~25 |
| **Ожидаемый OK** | ~15 | ~60 | ~40 |
| **N/A (server-level)** | ~8 | ~8 | ~8 |

Подробная ground truth таблица (83 проверки × 3 окружения) приведена в Приложении A.

### 3.3 Формулы

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)  
F1 Score  = 2 × Precision × Recall / (Precision + Recall)
```

### 3.4 Ожидаемые результаты

| Метрика | Целевое значение | Обоснование |
|---------|:---:|-------------|
| Precision | ≥ 95% | Минимум ложных срабатываний |
| Recall | ≥ 90% | Допускаются N/A проверки (server-level) |
| F1 | ≥ 92% | Баланс точности и полноты |

## 4. Эксперимент 2: Анализ векторов атак

### 4.1 Методология

1. Запустить `POST /api/scan-and-analyze` для vulnerable realm
2. Проверить что для каждого FULLY_ENABLED вектора все prerequisites действительно обнаружены
3. Запустить для hardened realm
4. Проверить что ни один вектор не FULLY_ENABLED

### 4.2 Ожидаемые результаты

| Вектор | Vulnerable | Hardened |
|--------|:---:|:---:|
| FULLY_ENABLED | ≥ 10 | 0 |
| PARTIALLY_ENABLED | ≥ 5 | ≤ 3 |
| MITIGATED | ≤ 5 | ≥ 17 |

## 5. Эксперимент 3: Функциональное тестирование

### 5.1 Персистентное хранилище

| Тест | Действие | Ожидание |
|------|---------|----------|
| F1 | POST /api/scan → GET /api/scans | Скан появляется в списке |
| F2 | GET /api/scans/{id} | Полный отчёт с findings |
| F3 | DELETE /api/scans/{id} → GET /api/scans/{id} | 404 |

### 5.2 Diff между сканами

| Тест | Действие | Ожидание |
|------|---------|----------|
| D1 | Скан vulnerable → Скан hardened → GET /api/scans/diff | resolvedFindings > 0, newFindings возможны |
| D2 | Скан A → тот же конфиг → Скан B → diff | unchangedFindings = все, new/resolved = 0 |

### 5.3 Baseline

| Тест | Действие | Ожидание |
|------|---------|----------|
| B1 | Создать baseline из скана → применить к тому же скану | actionable = 0 |
| B2 | Создать baseline из скана A → применить к скану B (новый realm) | actionable = новые findings |

### 5.4 SARIF Export

| Тест | Действие | Ожидание |
|------|---------|----------|
| S1 | GET /api/scans/{id}/sarif | Валидный SARIF v2.1.0 JSON |
| S2 | Проверить наличие rules, results, tool | Все секции заполнены |
| S3 | results.length == количество DETECTED findings | Соответствие |

### 5.5 gRPC External Modules

| Тест | Действие | Ожидание |
|------|---------|----------|
| G1 | Запустить Python module → перезапустить сканер | Лог: "Registered 2 external checks" |
| G2 | Запустить скан | CUSTOM-PY-001 и CUSTOM-PY-002 в результатах |
| G3 | Остановить Python module → запустить скан | Скан работает без ошибок (83 проверки вместо 85) |

### 5.6 Web UI

| Тест | Действие | Ожидание |
|------|---------|----------|
| U1 | GET / | Форма отображается корректно |
| U2 | POST /scan → результат | Findings + Attack Vectors табы |
| U3 | GET /history | Список сканов |
| U4 | GET /diff → сравнение | New/Resolved/Unchanged |
| U5 | GET /baselines → создать → применить | Filtered report |

## 6. Эксперимент 4: Сравнительный анализ

### 6.1 Сравнение с ручным аудитом

Независимый ручной аудит конфигурации vulnerable realm:
1. Эксперт проходит по чек-листу ASVS вручную
2. Документирует найденные проблемы
3. Сравнивает с результатом автоматического скана
4. Вычисляет покрытие = (автоматически найдено / всего найдено)

### 6.2 Время выполнения

| Метрика | Автоматический скан | Ручной аудит |
|---------|:---:|:---:|
| Время полного скана | ~5-10 сек | ~2-4 часа |
| Количество проверок | 83 | ~40-50 |
| Воспроизводимость | 100% | Зависит от эксперта |

## 7. Формат представления результатов

### Таблица 1: Precision/Recall по категориям

| Категория | Checks | TP | FP | FN | Precision | Recall | F1 |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Password (V6.1-V6.2) | 11 | | | | | | |
| Auth (V6.3-V6.4) | 8 | | | | | | |
| OTP (V6.5-V6.6) | 6 | | | | | | |
| Session (V7.x) | 12 | | | | | | |
| Authorization (V8.x) | 4 | | | | | | |
| Tokens (V9.x) | 8 | | | | | | |
| OAuth (V10.x) | 15 | | | | | | |
| Cryptography (V11.x) | 3 | | | | | | |
| Web (V3-4, V12-14) | 19 | | | | | | |
| **Итого** | **83** | | | | | | |

### Таблица 2: Активные векторы атак

| # | CAPEC | Атака | Vulnerable | Hardened | Default |
|---|-------|-------|:---:|:---:|:---:|
| 1 | CAPEC-49 | Password Brute Forcing | FULL | MITIGATED | ? |
| ... | ... | ... | ... | ... | ... |

### Таблица 3: Функциональные тесты

| Тест | Статус | Комментарий |
|------|:---:|-------------|
| F1 | PASS/FAIL | |
| ... | | |

## Приложение A: Ground Truth (заполняется перед экспериментом)

Для каждого check ID указать ожидаемый статус в каждом окружении:

| Check ID | Название | Vulnerable | Hardened | Default |
|----------|---------|:---:|:---:|:---:|
| 6.1.2 | Password Blacklist | DETECTED | OK | DETECTED |
| 6.2.1 | Min Password Length | DETECTED | OK | DETECTED |
| 6.2.2 | Password Change Enabled | DETECTED | OK | ? |
| ... | ... | ... | ... | ... |

Статусы: DETECTED, OK, ERROR, N/A (не применимо для данного окружения)
