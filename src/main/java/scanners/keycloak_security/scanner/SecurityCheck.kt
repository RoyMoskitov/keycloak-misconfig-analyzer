package scanners.keycloak_security.scanner

import scanners.keycloak_security.model.CheckContext
import scanners.keycloak_security.model.CheckResult
import scanners.keycloak_security.model.Severity

interface SecurityCheck {
    fun id(): String
    fun title(): String
    fun description(): String
    fun severity(): Severity
    fun run(context: CheckContext): CheckResult
}
