package scanners.keycloak_security.cli

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import org.springframework.boot.CommandLineRunner
import org.springframework.core.env.Environment
import org.springframework.stereotype.Component
import scanners.keycloak_security.scanner.KeycloakScanner
import scanners.keycloak_security.scanner.SarifExporter
import java.io.File

/**
 * CLI mode: если передан аргумент --cli, сканер выполняет скан,
 * выводит результат в stdout/файл и завершает процесс.
 *
 * Использование:
 *   java -jar scanner.jar --cli \
 *     --keycloak-audit.server-url=http://keycloak:8080 \
 *     --keycloak-audit.realm=my-realm \
 *     --keycloak-audit.client-id=admin-cli \
 *     --keycloak-audit.username=admin \
 *     --keycloak-audit.password=secret \
 *     --output=results.json \
 *     --format=json|sarif \
 *     --fail-on=10
 */
@Component
class CliScanRunner(
    private val scanner: KeycloakScanner,
    private val sarifExporter: SarifExporter,
    private val environment: Environment
) : CommandLineRunner {

    override fun run(vararg args: String) {
        if (!args.any { it == "--cli" }) return

        val outputFile = args.findArg("--output") ?: "results.json"
        val format = args.findArg("--format") ?: "json"
        val failOn = args.findArg("--fail-on")?.toIntOrNull() ?: -1

        System.err.println("Keycloak Security Scanner (CLI mode)")
        System.err.println("Target: ${environment.getProperty("keycloak-audit.server-url")}")
        System.err.println("Realm: ${environment.getProperty("keycloak-audit.realm")}")
        System.err.println("")

        val report = scanner.scan()

        val mapper = ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
        val content = when (format) {
            "sarif" -> mapper.writeValueAsString(sarifExporter.export(report))
            else -> mapper.writeValueAsString(report)
        }

        File(outputFile).writeText(content)
        System.err.println("Results saved to: $outputFile ($format)")

        val detected = report.summary.detected
        val total = report.summary.totalChecks
        val errors = report.summary.errors

        System.err.println("")
        System.err.println("Total: $total | Detected: $detected | OK: ${report.summary.ok} | Errors: $errors")

        // Output summary to stdout for CI/CD parsing
        println("DETECTED=$detected")
        println("TOTAL=$total")
        println("ERRORS=$errors")

        if (failOn >= 0 && detected > failOn) {
            System.err.println("")
            System.err.println("FAILED: $detected findings exceed threshold of $failOn")
            System.exit(1)
        }

        System.exit(0)
    }

    private fun Array<out String>.findArg(prefix: String): String? {
        return find { it.startsWith("$prefix=") }?.substringAfter("=")
    }
}
