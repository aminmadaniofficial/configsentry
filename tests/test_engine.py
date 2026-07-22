import pytest
import httpx
from configsentry.analyzers.headers import HeaderAnalyzer
from configsentry.core.models import RiskLevel


@pytest.mark.asyncio
async def test_header_analyzer_detects_missing_headers():
    """
    Test that HeaderAnalyzer correctly identifies missing security headers in response.
    """
    analyzer = HeaderAnalyzer()
    
    # Mock HTTP response with empty headers
    dummy_request = httpx.Request("GET", "https://example.com")
    mock_response = httpx.Response(status_code=200, headers={}, request=dummy_request)
    
    issues = await analyzer.analyze(mock_response)
    
    assert len(issues) == 4
    header_titles = [issue.title for issue in issues]
    assert any("Strict-Transport-Security" in title for title in header_titles)
    assert any("Content-Security-Policy" in title for title in header_titles)


@pytest.mark.asyncio
async def test_header_analyzer_passes_when_headers_present():
    """
    Test that HeaderAnalyzer returns no issues when all security headers are set.
    """
    analyzer = HeaderAnalyzer()
    
    mock_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    dummy_request = httpx.Request("GET", "https://example.com")
    mock_response = httpx.Response(status_code=200, headers=mock_headers, request=dummy_request)
    
    issues = await analyzer.analyze(mock_response)
    
    assert len(issues) == 0