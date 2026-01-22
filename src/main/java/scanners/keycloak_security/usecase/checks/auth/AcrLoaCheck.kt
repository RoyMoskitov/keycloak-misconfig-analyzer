//package scanners.keycloak_security.usecase.checks.auth
//
//import org.springframework.stereotype.Component
//import scanners.keycloak_security.domain.model.*
//import scanners.keycloak_security.usecase.checks.SecurityCheck
//
//        @Component
//        class AcrLoaCheck : SecurityCheck {
//
//            override fun id() = "6.8.4"
//            override fun title() = "Проверка уровня аутентификации от IdP"
//            override fun description() = "Проверка настроек ACR (Authentication Context Class Reference)"
//            override fun severity() = Severity.LOW // Низкая, так как это рекомендация
//
//            override fun run(context: CheckContext): CheckResult {
//                val start = System.currentTimeMillis()
//                val realm = context.adminService.getRealm()
//
//                val acrLoaMap = realm.acrLoaMap
//                val clients = context.adminService.getClients()
//
//                val findings = mutableListOf<Finding>()
//
//                // Проверка наличия ACR Loa Map
//                if (acrLoaMap.isNullOrEmpty()) {
//                    findings.add(
//                        Finding(
//                            id = id(),
//                            title = "ACR Loa Map не настроен",
//                            description = "Отсутствует маппинг уровней аутентификации",
//                            severity = severity(),
//                            status = CheckStatus.DETECTED,
//                            realm = context.realmName,
//                            evidence = listOf(
//                                Evidence("acrLoaMap", "null или пустой")
//                            ),
//                            recommendation = "Настройте acrLoaMap для определения уровней доверия аутентификации"
//                        )
//                    )
//                } else {
//                    // Проверка, что мап содержит стандартные уровни
//                    val standardLevels = listOf("0", "1", "2", "3", "4")
//                    val missingLevels = standardLevels.filter { !acrLoaMap.containsKey(it) }
//
//                    if (missingLevels.isNotEmpty()) {
//                        findings.add(
//                            Finding(
//                                id = id(),
//                                title = "Неполный ACR Loa Map",
//                                description = "Отсутствуют стандартные уровни аутентификации: ${missingLevels.joinToString()}",
//                                severity = Severity.LOW,
//                                status = CheckStatus.DETECTED,
//                                realm = context.realmName,
//                                evidence = listOf(
//                                    Evidence("acrLoaMap", acrLoaMap.toString()),
//                                    Evidence("missingLevels", missingLevels.toString())
//                                ),
//                                recommendation = "Добавьте стандартные уровни аутентификации (0-4) в acrLoaMap"
//                            )
//                        )
//                    }
//                }
//
//                // Проверка клиентов на использование acr_values
//                val clientsWithAcr = clients.filter { client ->
//                    client.attributes?.get("acr.loa.map") != null ||
//                            client.attributes?.get("default.acr.values") != null
//                }
//
//                if (clientsWithAcr.isEmpty()) {
//                    findings.add(
//                        Finding(
//                            id = id(),
//                            title = "Клиенты не используют ACR",
//                            description = "Ни один клиент не настроен на использование ACR значений",
//                            severity = Severity.LOW,
//                            status = CheckStatus.DETECTED,
//                            realm = context.realmName,
//                            evidence = listOf(
//                                Evidence("totalClients", clients.size.toString()),
//                                Evidence("clientsWithAcr", "0")
//                            ),
//                            recommendation = "Настройте клиенты на использование acr_values для указания требуемого уровня аутентификации"
//                        )
//                    )
//                } else {
//                    // Логируем, но не считаем ошибкой
//                    findings.add(
//                        Finding(
//                            id = id(),
//                            title = "ACR используется клиентами",
//                            description = "${clientsWithAcr.size} клиентов используют ACR значения",
//                            severity = Severity.INFO,
//                            status = CheckStatus.OK,
//                            realm = context.realmName,
//                            evidence = listOf(
//                                Evidence("clientsWithAcr", clientsWithAcr.size.toString()),
//                                Evidence("totalClients", clients.size.toString())
//                            ),
//                            recommendation = null
//                        )
//                    )
//                }
//
//                val hasErrors = findings.any { it.severity >= Severity.MEDIUM }
//
//                return if (hasErrors) {
//                    CheckResult(
//                        checkId = id(),
//                        status = CheckStatus.DETECTED,
//                        findings = findings,
//                        durationMs = System.currentTimeMillis() - start
//                    )
//                } else if (findings.isNotEmpty() && findings.all { it.severity == Severity.INFO }) {
//                    CheckResult(
//                        checkId = id(),
//                        status = CheckStatus.OK,
//                        findings = findings,
//                        durationMs = System.currentTimeMillis() - start
//                    )
//                } else {
//                    CheckResult(
//                        checkId = id(),
//                        status = CheckStatus.OK,
//                        durationMs = System.currentTimeMillis() - start
//                    )
//                }
//            }
//        }