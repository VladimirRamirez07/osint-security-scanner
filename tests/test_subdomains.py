import pytest
from unittest.mock import patch, MagicMock
from scanner.subdomain_checker import check_single_subdomain, scan_subdomains

class TestSubdomainChecker:
    def test_subdomain_resolves(self):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "93.184.216.34"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Welcome"
        mock_response.url = "https://www.example.com"

        with patch("dns.resolver.resolve", return_value=[mock_answer]), \
             patch("requests.get", return_value=mock_response):
            result = check_single_subdomain("www", "example.com")
            assert result.resolves is True
            assert result.ip == "93.184.216.34"
            assert result.takeover_risk is False

    def test_subdomain_not_exists(self):
        import dns.resolver
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
            result = check_single_subdomain("fakesub", "example.com")
            assert result.resolves is False

    def test_takeover_detection(self):
        mock_dns = MagicMock()
        mock_dns.to_text.return_value = "1.2.3.4"

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "There isn't a GitHub Pages site here"
        mock_response.url = "https://old.example.com"

        with patch("dns.resolver.resolve", return_value=[mock_dns]), \
             patch("requests.get", return_value=mock_response):
            result = check_single_subdomain("old", "example.com")
            assert result.takeover_risk is True
            assert "github.io" in result.takeover_service

    def test_scan_returns_result_object(self):
        import dns.resolver
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
            result = scan_subdomains("example.com", max_workers=5)
            assert result.domain == "example.com"
            assert result.total_checked > 0
            assert isinstance(result.found, list)