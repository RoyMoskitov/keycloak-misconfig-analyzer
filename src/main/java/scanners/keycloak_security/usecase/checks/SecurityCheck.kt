package scanners.keycloak_security.usecase.checks

import scanners.keycloak_security.domain.model.CheckContext
import scanners.keycloak_security.domain.model.CheckResult
import scanners.keycloak_security.domain.model.Severity

interface SecurityCheck {
    fun id(): String
    fun title(): String
    fun description(): String
    fun severity(): Severity
    fun run(context: CheckContext): CheckResult
}
