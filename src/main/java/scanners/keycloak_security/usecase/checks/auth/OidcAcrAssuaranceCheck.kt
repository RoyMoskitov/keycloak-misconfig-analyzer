//package scanners.keycloak_security.usecase.checks.auth
//
//import org.springframework.stereotype.Component
//import scanners.keycloak_security.domain.model.*
//import scanners.keycloak_security.usecase.checks.SecurityCheck
//
//@Component
//class OidcAcrAssuranceCheck : SecurityCheck {
//
//    override fun id() = "6.8.4"
//    override fun title() = "Проверка поддержки и валидации уровня уверенности (ACR) в Keycloak"
//    override fun description() =
//        "Проверка, что Keycloak правильно настраивает ACR для OIDC, " +
//                "включая наличие client scope, mapping ACR↔LoA и включение для всех клиентов"
//
//    override fun severity() = Severity.MEDIUM
//
//    override fun run(context: CheckContext): CheckResult {
//        val start = System.currentTimeMillis()
//        val realm = context.adminService.getRealm()
//        val findings = mutableListOf<Finding>()
//
//        // 1) Проверка ACR client scope
//        val realmClients = context.adminService.getClients()
//        realmClients.forEach { client ->
//            val scopes = client.defaultClientScopes + client.optionalClientScopes
//            if (!scopes.contains("acr")) {
//                findings.add(
//                    Finding(
//                        id = id(),
//                        title = "ACR scope не привязан к клиенту",
//                        description = "Клиент `${client.clientId}` не содержит `acr` в client scopes.",
//                        severity = Severity.MEDIUM,
//                        status = CheckStatus.DETECTED,
//                        realm = context.realmName,
//                        clientId = client.clientId
//                    )
//                )
//            }
//        }
//
//        val acrMapping = realm.
//        if (acrMapping == null || acrMapping.isEmpty()) {
//            findings.add(
//                Finding(
//                    id = id(),
//                    title = "Не задано отображение ACR↔LoA",
//                    description = "Realm не содержит ACR to LoA mapping, что может привести к отсутствию step-up.",
//                    severity = Severity.MEDIUM,
//                    status = CheckStatus.DETECTED,
//                    realm = context.realmName
//                )
//            )
//        }
//
//        return if (findings.isNotEmpty()) {
//            CheckResult(
//                checkId = id(),
//                status = CheckStatus.DETECTED,
//                findings = findings,
//                durationMs = System.currentTimeMillis() - start
//            )
//        } else {
//            CheckResult(checkId = id(), status = CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
//        }
//    }
//}
