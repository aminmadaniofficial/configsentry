import httpx
from configsentry.analyzers.base import BaseAnalyzer
from configsentry.core.models import SecurityIssue, RiskLevel

class HeaderAnalyzer(BaseAnalyzer):
    """
    Audits HTTP response headers against OWASP security best practices.
    """

    RECOMMENDED_HEADERS = {
        "Strict-Transport-Security": (
            RiskLevel.HIGH,
            "Enforces HTTPS connections to prevent Man-in-the-Middle attacks.",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
        ),
        "Content-Security-Policy": (
            RiskLevel.HIGH,
            "Prevents Cross-Site Scripting (XSS) and data injection attacks.",
            "Define a strict Content-Security-Policy header restriction."
        ),
        "X-Frame-Options": (
            RiskLevel.MEDIUM,
            "Protects against Clickjacking attacks.",
            "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        ),
        "X-Content-Type-Options": (
            RiskLevel.LOW,
            "Prevents MIME-sniffing vulnerabilities.",
            "Set 'X-Content-Type-Options: nosniff'."
        )
    }

    async def analyze(self, response: httpx.Response) -> list[SecurityIssue]:
        issues = []
        headers = response.headers

        for header_name, (risk, desc, remediation) in self.RECOMMENDED_HEADERS.items():
            if header_name.lower() not in [h.lower() for h in headers.keys()]:
                issues.append(
                    SecurityIssue(
                        title=f"Missing Security Header: {header_name}",
                        risk_level=risk,
                        description=desc,
                        remediation=remediation
                    )
                )

        return issues