import pytest
from unittest.mock import patch, MagicMock
from scanner.http_checker import scan_http

class TestHTTPScanner:
    def _mock_response(self, headers: dict, url: str = "https://example.com"):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = url
        mock_resp.headers = headers
        return mock_resp

    def test_all_security_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block",
            "Server": "nginx"
        }
        with patch("requests.get", return_value=self._mock_response(headers)):
            result = scan_http("example.com")
            assert result.score > 90
            assert result.https_enabled is True
            assert len(result.headers_found) == 7
            assert len(result.headers_missing) == 0

    def test_no_security_headers(self):
        with patch("requests.get", return_value=self._mock_response({})):
            result = scan_http("example.com")
            assert len(result.headers_found) == 0
            assert len(result.headers_missing) == 7

    def test_connection_error(self):
        import requests
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError):
            result = scan_http("nonexistent.example.com")
            assert result.error is not None
            assert result.score == 0

    def test_timeout_error(self):
        import requests
        with patch("requests.get", side_effect=requests.exceptions.Timeout):
            result = scan_http("slow.example.com")
            assert result.error is not None

    def test_https_enabled(self):
        with patch("requests.get", return_value=self._mock_response(
            {}, url="https://example.com"
        )):
            result = scan_http("example.com")
            assert result.https_enabled is True