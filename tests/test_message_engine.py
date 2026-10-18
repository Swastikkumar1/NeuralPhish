"""
Unit Tests for NeuralPhish MessageScanner & Social Engineering Analyzer
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "NeuralPhish")))

from scanner_engine import NeuralPhishEngine
from message_engine import MessageScanner


@pytest.fixture(scope="module")
def engine():
    return NeuralPhishEngine()


class TestUrlExtraction:
    """Tests URL extraction from diverse messaging platforms."""

    def test_extract_standard_urls(self):
        text = "Hello! Check out https://github.com/project and http://test.org for info."
        urls = MessageScanner.extract_urls(text)
        assert "https://github.com/project" in urls
        assert "http://test.org" in urls

    def test_extract_defanged_urls(self):
        text = "Suspicious invoice attached: hxxps://invoice-vault[.]top/doc"
        urls = MessageScanner.extract_urls(text)
        assert len(urls) == 1
        assert urls[0] == "https://invoice-vault.top/doc"

    def test_extract_markdown_and_html_urls(self):
        text = "Click <a href='https://evil-portal.xyz/login'>here</a> or check [Account](https://bad-bank.xyz)"
        urls = MessageScanner.extract_urls(text)
        assert "https://evil-portal.xyz/login" in urls
        assert "https://bad-bank.xyz" in urls

    def test_extract_schemeless_urls_with_punctuation(self):
        text = "Verify your account at bit.ly/3x918F! Or visit www.fake-login.com/auth."
        urls = MessageScanner.extract_urls(text)
        assert len(urls) >= 2
        # Punctuation (! and .) should be cleanly stripped from the URL
        assert any("bit.ly/3x918F" in u for u in urls)
        assert any("www.fake-login.com/auth" in u for u in urls)


class TestSocialEngineeringAnalysis:
    """Tests urgency, financial lures, and brand impersonation detection."""

    def test_brand_impersonation_detection(self):
        text = "URGENT: Your Netflix membership will be cancelled! Update at https://netflix-billing-renew.xyz/login"
        urls = ["https://netflix-billing-renew.xyz/login"]
        analysis = MessageScanner.analyze_social_engineering(text, urls)
        
        assert analysis["has_brand_impersonation"] is True
        assert len(analysis["impersonation_flags"]) > 0
        assert analysis["impersonation_flags"][0]["brand"] == "Netflix"
        assert "urgent" in analysis["urgency_triggers"]

    def test_legitimate_brand_does_not_flag_impersonation(self):
        text = "Here is the official Netflix help page: https://help.netflix.com/en"
        urls = ["https://help.netflix.com/en"]
        analysis = MessageScanner.analyze_social_engineering(text, urls)
        
        assert analysis["has_brand_impersonation"] is False
        assert len(analysis["impersonation_flags"]) == 0

    def test_financial_and_prize_scam_triggers(self):
        text = "Congratulations! You won a $1,000 cash prize in our lottery giveaway!"
        analysis = MessageScanner.analyze_social_engineering(text, [])
        assert "won" in analysis["financial_lures"]
        assert "prize" in analysis["financial_lures"]
        assert "lottery" in analysis["financial_lures"]


class TestEndToEndMessageAnalysis:
    """Tests consolidated message safety assessment."""

    def test_phishing_message_evaluation(self, engine):
        text = "URGENT from PayPal: Your account has been suspended! Verify immediately at http://paypal-verify-account.top/login"
        result = MessageScanner.analyze_message(text, engine)
        
        assert result["verdict"] == "DANGEROUS"
        assert result["status"] == "danger"
        assert result["risk_score"] >= 80.0
        assert result["social_engineering"]["has_brand_impersonation"] is True
        assert len(result["recommendations"]) > 0

    def test_benign_message_evaluation(self, engine):
        text = "Hey team, check out the documentation on https://python.org for details."
        result = MessageScanner.analyze_message(text, engine)
        
        assert result["verdict"] == "SAFE"
        assert result["status"] == "safe"
        assert result["risk_score"] < 20.0

    def test_empty_message_returns_clean(self, engine):
        result = MessageScanner.analyze_message("", engine)
        assert result["verdict"] == "CLEAN"
        assert result["urls_found"] == 0
