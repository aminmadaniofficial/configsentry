import datetime
import httpx
from configsentry.core.models import ScanResult
from configsentry.analyzers.headers import HeaderAnalyzer
from configsentry.analyzers.ssl_tls import SSLAnalyzer

class ScanEngine:
    """
    Orchestrates execution of registered analyzers for target URLs.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.analyzers = [
            HeaderAnalyzer(),
            SSLAnalyzer(),
        ]

    async def run_scan(self, target_url: str) -> ScanResult:
        """
        Executes HTTP request and runs all registered security analyzers asynchronously.
        """
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
            except httpx.RequestError as exc:
                pass

        return result