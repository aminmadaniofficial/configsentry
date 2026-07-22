import ssl
import socket
import datetime
import urllib.parse
from configsentry.analyzers.base import BaseAnalyzer
from configsentry.core.models import SecurityIssue, RiskLevel

class SSLAnalyzer(BaseAnalyzer):
    """
    Checks SSL/TLS certificate validity and expiry timeframe.
    """

    async def analyze(self, response) -> list[SecurityIssue]:
        issues = []
        parsed_url = urllib.parse.urlparse(str(response.url))

        # SSL checks apply strictly to HTTPS schemes
        if parsed_url.scheme.lower() != "https":
            issues.append(
                SecurityIssue(
                    title="Insecure Transport Protocol (HTTP)",
                    risk_level=RiskLevel.HIGH,
                    description="Target does not use HTTPS by default. Traffic is unencrypted.",
                    remediation="Configure SSL/TLS certificate and redirect all HTTP traffic to HTTPS."
                )
            )
            return issues

        hostname = parsed_url.hostname
        port = parsed_url.port or 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                    cert = sslsock.getpeercert()
                    
                    # Parse certificate expiration timestamp
                    expire_date_str = cert['notAfter']
                    expire_date = datetime.datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.datetime.utcnow()).days

                    if days_left < 0:
                        issues.append(
                            SecurityIssue(
                                title="Expired SSL/TLS Certificate",
                                risk_level=RiskLevel.HIGH,
                                description=f"Certificate expired {abs(days_left)} days ago.",
                                remediation="Renew the SSL/TLS certificate immediately."
                            )
                        )
                    elif days_left < 15:
                        issues.append(
                            SecurityIssue(
                                title="SSL/TLS Certificate Expiring Soon",
                                risk_level=RiskLevel.MEDIUM,
                                description=f"Certificate expires in {days_left} days.",
                                remediation="Schedule SSL certificate renewal before expiration."
                            )
                        )

        except Exception as err:
            issues.append(
                SecurityIssue(
                    title="SSL/TLS Handshake/Validation Error",
                    risk_level=RiskLevel.HIGH,
                    description=f"Could not establish secure SSL connection: {str(err)}",
                    remediation="Ensure valid SSL certificate chain is installed on web server."
                )
            )

        return issues