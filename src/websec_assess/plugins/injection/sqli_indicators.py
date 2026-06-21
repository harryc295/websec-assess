"""SQL injection *indicator*: appends a single quote and looks for a known
database error signature that wasn't present in the unmodified baseline
response. Error-based detection only -- no UNION/boolean/time-based
extraction, no destructive queries."""
from __future__ import annotations

from websec_assess.core.models import Evidence, PluginResult
from websec_assess.core.plugin import Plugin, PluginContext, PluginRegistry
from websec_assess.core.severity import Confidence, Severity
from websec_assess.plugins.injection._common import build_url, budget_for, candidate_params

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unterminated quoted string",
    "pg_query():",
    "unclosed quotation mark",
    "microsoft sql server",
    "ora-01756",
    "ora-00933",
    "sqlite3.operationalerror",
    "unrecognized token",
    "sqlstate[",
]
PAYLOADS = ["'", "''"]


@PluginRegistry.register
class SqliIndicatorsPlugin(Plugin):
    name = "injection.sqli_indicators"
    category = "injection"
    description = "Appends quote characters to each parameter and checks for a new database error signature vs. baseline."
    requires_active_probes = True

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult(plugin=self.name)

        for base, name, original, params in candidate_params(ctx, budget_for(ctx)):
            baseline_url = build_url(base, params, name, original)
            baseline = await ctx.http.get(baseline_url)
            baseline_text = (baseline.text or "").lower() if baseline else ""

            for payload in PAYLOADS:
                test_url = build_url(base, params, name, original + payload)
                resp = await ctx.http.get(test_url)
                if resp is None or not resp.text:
                    continue
                body = resp.text.lower()
                new_signatures = [s for s in ERROR_SIGNATURES if s in body and s not in baseline_text]
                if new_signatures:
                    result.findings.append(
                        ctx.finding(
                            category="injection",
                            title=f"SQL injection indicator on parameter '{name}'",
                            description=(
                                f"Appending a quote character to '{name}' produced a database error message that "
                                "was not present in the baseline response, suggesting unsanitised input reaches a SQL query."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            affected_url=test_url,
                            evidence=[Evidence(description="New error signature vs. baseline", matched_value=new_signatures[0])],
                            remediation="Use parameterised queries/prepared statements exclusively; never build SQL via string concatenation.",
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            cwe="CWE-89",
                            owasp="A03:2021-Injection",
                        )
                    )
                    break
        return result
