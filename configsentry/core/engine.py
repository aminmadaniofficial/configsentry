import datetime
import httpx
from configsentry.core.models import ScanResult, SecurityIssue, RiskLevel
from configsentry.analyzers.headers import HeaderAnalyzer
from configsentry.analyzers.ssl_tls import SSLAnalyzer
from configsentry.analyzers.server_info import ServerInfoAnalyzer
class ScanEngine:
    """
    Orchestrates execution of registered analyzers for target URLs.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.analyzers = [
            HeaderAnalyzer(),
            SSLAnalyzer(),
            ServerInfoAnalyzer(),
        ]

    async def run_scan(self, target_url: str) -> ScanResult:
        result = ScanResult(
            target_url=target_url,
            scan_timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        )

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                response = await client.get(target_url, follow_redirects=True)
                for analyzer in self.analyzers:
                    findings = await analyzer.analyze(response)
                    result.issues.extend(findings)

            except httpx.ConnectError:
                result.issues.append(
                    SecurityIssue(
                        title="Target Unreachable / DNS Failure",
                        risk_level=RiskLevel.HIGH,
                        description="Failed to resolve domain name or establish TCP connection.",
                        remediation="Verify target URL spelling, domain availability, and network routing."
                    )
                )
            except httpx.TimeoutException:
                result.issues.append(
                    SecurityIssue(
                        title="Connection Timeout",
                        risk_level=RiskLevel.MEDIUM,
                        description="Target server did not respond within specified timeout limit.",
                        remediation="Check server availability or increase scan timeout using -t flag."
                    )
                )
            except httpx.RequestError as exc:
                result.issues.append(
                    SecurityIssue(
                        title="Network Request Failure",
                        risk_level=RiskLevel.LOW,
                        description=f"HTTP request failed: {str(exc)}",
                        remediation="Inspect network connection and target availability."
                    )
                )

        return result