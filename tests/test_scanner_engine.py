"""
Unit & Integration Tests for NeuralPhish Hybrid Detection Engine
"""

import pytest
import sys
import os

# Ensure import works
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "NeuralPhish")))

from scanner_engine import NeuralPhishEngine


@pytest.fixture(scope="module")
def engine():
    """Initializes a shared NeuralPhishEngine fixture for test execution."""
    return NeuralPhishEngine()


class TestShannonEntropy:
    """Tests the Shannon Entropy algorithmic randomness calculation."""

    def test_zero_entropy_for_empty_string(self):
        assert NeuralPhishEngine.calculate_shannon_entropy("") == 0.0

    def test_low_entropy_for_repeated_characters(self):
        # Monotonous strings have low entropy
        entropy = NeuralPhishEngine.calculate_shannon_entropy("aaaaaaaaaa")
        assert entropy == 0.0

    def test_high_entropy_for_dga_domains(self):
        # Random DGA string has elevated entropy
        entropy = NeuralPhishEngine.calculate_shannon_entropy("qxz98kf71b2ml4w0p9")
        assert entropy > 3.5


class TestLexicalFeatures:
    """Tests lexical parsing and security heuristic extraction."""

    def test_ip_address_host_detection(self, engine):
        features = engine.extract_lexical_features("http://192.168.1.1/admin")
        assert features["is_ip_address"] is True
        assert features["is_https"] is False

    def test_punycode_homoglyph_detection(self, engine):
        features = engine.extract_lexical_features("https://xn--pple-43d.com/login")
        assert features["is_punycode"] is True

    def test_suspicious_tld_flagging(self, engine):
        features = engine.extract_lexical_features("http://bank-verification.xyz/auth")
        assert features["is_suspicious_tld"] is True
        assert features["tld"] == "xyz"

    def test_legitimate_https_parsing(self, engine):
        features = engine.extract_lexical_features("https://github.com/torvalds/linux")
        assert features["is_https"] is True
        assert features["is_ip_address"] is False
        assert features["is_punycode"] is False
        assert features["is_known_safe"] is True


class TestMachineLearningInference:
    """Tests NLP tokenization, stemming, vectorization, and model inference."""

    def test_safe_domain_prediction(self, engine):
        result = engine.analyze("https://google.com")
        assert result["verdict"] == "SAFE"
        assert result["status"] == "safe"
        assert result["risk_score"] < 25.0
        assert result["ml_analysis"]["benign_probability_pct"] > 50.0

    def test_dangerous_phishing_prediction(self, engine):
        url = "http://paypal-verification-account-security-update.xyz/login"
        result = engine.analyze(url)
        assert result["verdict"] == "DANGEROUS"
        assert result["status"] == "danger"
        assert result["risk_score"] >= 70.0
        assert len(result["threat_indicators"]) > 0

    def test_explainable_ai_token_attribution(self, engine):
        url = "http://paypal-verification-account-security-update.xyz/login"
        result = engine.analyze(url)
        ml = result["ml_analysis"]
        assert "token_attributions" in ml
        assert len(ml["token_attributions"]) > 0
        
        # Verify that malicious tokens (e.g., 'paypal', 'login') have positive log-odds
        malicious = ml["top_malicious_tokens"]
        assert any(t in malicious for t in ["paypal", "login", "verif", "account"])

    def test_empty_url_raises_value_error(self, engine):
        with pytest.raises(ValueError):
            engine.analyze("")


class TestBatchScanning:
    """Tests bulk URL scanning capability."""

    def test_batch_scan_mixed_urls(self, engine):
        urls = [
            "https://google.com",
            "http://paypal-security-update.xyz/login",
            "https://python.org"
        ]
        results = engine.scan_batch(urls)
        assert len(results) == 3
        assert results[0]["verdict"] == "SAFE"
        assert results[1]["verdict"] == "DANGEROUS"
        assert results[2]["verdict"] == "SAFE"
