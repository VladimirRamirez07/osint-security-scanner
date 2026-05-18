import pytest
from unittest.mock import patch, MagicMock
from scanner.dns_checker import (
    check_spf, check_dkim, check_dmarc,
    calculate_score, scan_dns, DNSResult
)

class TestSPF:
    def test_spf_valid_with_all_minus(self):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '"v=spf1 include:_spf.google.com -all"'
        with patch("dns.resolver.resolve", return_value=[mock_answer]):
            record, valid = check_spf("example.com")
            assert record is not None
            assert valid is True

    def test_spf_weak_with_tilde(self):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '"v=spf1 include:_spf.google.com ~all"'
        with patch("dns.resolver.resolve", return_value=[mock_answer]):
            record, valid = check_spf("example.com")
            assert record is not None
            assert valid is True

    def test_spf_not_found(self):
        with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
            record, valid = check_spf("nonexistent.example.com")
            assert record is None
            assert valid is False

class TestDMARC:
    def test_dmarc_reject_policy(self):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
        with patch("dns.resolver.resolve", return_value=[mock_answer]):
            record, valid, policy = check_dmarc("example.com")
            assert record is not None
            assert valid is True
            assert policy == "reject"

    def test_dmarc_quarantine_policy(self):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '"v=DMARC1; p=quarantine;"'
        with patch("dns.resolver.resolve", return_value=[mock_answer]):
            record, valid, policy = check_dmarc("example.com")
            assert valid is True
            assert policy == "quarantine"

    def test_dmarc_none_policy(self):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '"v=DMARC1; p=none;"'
        with patch("dns.resolver.resolve", return_value=[mock_answer]):
            record, valid, policy = check_dmarc("example.com")
            assert valid is False
            assert policy == "none"

    def test_dmarc_not_found(self):
        with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
            record, valid, policy = check_dmarc("nonexistent.example.com")
            assert record is None
            assert valid is False
            assert policy == "none"

class TestScoring:
    def test_perfect_score(self):
        result = DNSResult(domain="example.com")
        result.spf = "v=spf1 -all"
        result.spf_valid = True
        result.dkim = "v=DKIM1; p=abc123"
        result.dkim_valid = True
        result.dmarc = "v=DMARC1; p=reject"
        result.dmarc_valid = True
        result.dmarc_policy = "reject"
        score = calculate_score(result)
        assert score == 100

    def test_zero_score(self):
        result = DNSResult(domain="example.com")
        score = calculate_score(result)
        assert score == 0

    def test_partial_score(self):
        result = DNSResult(domain="example.com")
        result.spf = "v=spf1 ~all"
        result.spf_valid = True
        result.dmarc_policy = "none"
        score = calculate_score(result)
        assert score > 0
        assert score < 100