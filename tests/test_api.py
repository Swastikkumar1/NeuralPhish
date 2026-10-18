"""
Integration Tests for NeuralPhish Flask REST API Endpoints
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "NeuralPhish")))

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestPublicEndpoints:
    """Tests health, model info, and dashboard rendering."""

    def test_dashboard_renders(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"NeuralPhish" in response.data

    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"
        assert data["engine_loaded"] is True

    def test_model_info(self, client):
        response = client.get("/api/model-info")
        assert response.status_code == 200
        data = response.get_json()
        assert "architecture" in data
        assert "classifier" in data


class TestScanEndpoint:
    """Tests the /api/scan endpoint."""

    def test_scan_safe_url(self, client):
        response = client.post("/api/scan", json={"url": "https://google.com"})
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["data"]["verdict"] == "SAFE"

    def test_scan_malicious_url(self, client):
        url = "http://paypal-verification-account-security-update.xyz/login"
        response = client.post("/api/scan", json={"url": url})
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["data"]["verdict"] == "DANGEROUS"

    def test_scan_missing_url_returns_400(self, client):
        response = client.post("/api/scan", json={})
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data


class TestScanMessageEndpoint:
    """Tests the /api/scan-message endpoint."""

    def test_scan_message_with_phishing_link(self, client):
        msg = "URGENT: Your Netflix account has been suspended! Update payment at https://netflix-update.xyz/auth"
        response = client.post("/api/scan-message", json={"message": msg})
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["data"]["verdict"] == "DANGEROUS"
        assert data["data"]["social_engineering"]["has_brand_impersonation"] is True

    def test_scan_message_missing_field_returns_400(self, client):
        response = client.post("/api/scan-message", json={})
        assert response.status_code == 400


class TestBatchScanEndpoint:
    """Tests the /api/batch-scan endpoint."""

    def test_valid_batch_scan(self, client):
        payload = {"urls": ["https://google.com", "https://python.org"]}
        response = client.post("/api/batch-scan", json=payload)
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["count"] == 2
        assert "summary" in data

    def test_batch_limit_exceeded_returns_400(self, client):
        urls = [f"https://example{i}.com" for i in range(55)]
        response = client.post("/api/batch-scan", json={"urls": urls})
        assert response.status_code == 400
