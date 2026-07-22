import httpx
from configsentry.analyzers.base import BaseAnalyzer
from configsentry.core.models import SecurityIssue, RiskLevel

class ServerInfoAnalyzer(BaseAnalyzer):
    """
    Detects information disclosure in Server and X-Powered-By HTTP response headers.
    """

    async def analyze(self, response: httpx.Response) -> list[SecurityIssue]:
        issues = []
        headers = response.headers

        # Check for Server header version leakage
        server_header = headers.get("Server")
        if server_header:
            # If server header contains numbers, it's likely disclosing exact version
            if any(char.isdigit() for char in server_header):
                issues.append(
                    SecurityIssue(
                        title="Server Version Information Disclosure",
                        risk_level=RiskLevel.LOW,
                        description=f"Server header exposes software version: '{server_header}'.",
                        remediation="Configure web server to obscure or remove exact version numbers in 'Server' header."
                    )
                )

        # Check for X-Powered-By header leakage
        powered_by = headers.get("X-Powered-By")
        if powered_by:
            issues.append(
                SecurityIssue(
                    title="Technology Stack Disclosure (X-Powered-By)",
                    risk_level=RiskLevel.LOW,
                    description=f"Header exposes backend technology: '{powered_by}'.",
                    remediation="Remove 'X-Powered-By' header in backend application configuration."
                )
            )

        return issues