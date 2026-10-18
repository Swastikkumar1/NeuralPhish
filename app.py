"""
NeuralPhish Web Application & REST API
Exposes endpoints for interactive URL scanning, batch threat analysis,
messenger / email scam detection, and real-time desktop clipboard scanning.
"""

import os
import sys
from typing import Tuple, Dict, Any
from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_cors import CORS

from scanner_engine import NeuralPhishEngine
from message_engine import MessageScanner

# Determine base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Initialize Flask application configured to serve index.html directly
app = Flask(
    __name__,
    template_folder=BASE_DIR,
    static_folder=BASE_DIR,
    static_url_path="",
)
CORS(app)

# Initialize detection engine
try:
    engine = NeuralPhishEngine()
    print("[+] NeuralPhish Engine successfully initialized with trained models.")
except Exception as e:
    print(f"[!] Warning: Could not initialize NeuralPhishEngine: {e}", file=sys.stderr)
    engine = None


@app.route("/", methods=["GET"])
def index():
    """Serves the NeuralPhish security dashboard."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint for container / orchestrator probes."""
    return jsonify({
        "status": "healthy",
        "service": "NeuralPhish Security Scanner API",
        "engine_loaded": engine is not None,
        "message_engine_ready": True,
        "version": "2.1.0"
    }), 200


@app.route("/api/model-info", methods=["GET"])
def model_info():
    """Returns technical metadata regarding the ML architecture and training."""
    if engine is None:
        return jsonify({"error": "Engine not initialized"}), 500

    return jsonify({
        "architecture": "Hybrid Defense-in-Depth (NLP Machine Learning + Lexical Heuristics + Social Engineering Lures)",
        "classifier": type(engine.model).__name__,
        "vectorizer": type(engine.vectorizer).__name__,
        "vocabulary_size": len(engine.vectorizer.vocabulary_) if hasattr(engine.vectorizer, "vocabulary_") else "Unknown",
        "training_dataset_size": "549,346 URLs (Phishing Site URLs benchmark)",
        "training_classes": list(engine.model.classes_) if hasattr(engine.model, "classes_") else ["bad", "good"],
        "benchmark_accuracy": "96.56% (MultinomialNB) / 95.75% (Logistic Regression)",
        "preprocessing_pipeline": [
            "Protocol & WWW prefix normalization",
            "Defanged URL restoration (hxxp, [.], [slash])",
            "Regex Alphabetic Tokenization (RegexpTokenizer [A-Za-z]+)",
            "English Snowball Stemming",
            "Count Vectorization (N-gram Bag of Words)",
            "Shannon Entropy calculation",
            "Cybersecurity lexical threat scoring",
            "Brand impersonation & social engineering correlation"
        ]
    }), 200


@app.route("/api/scan", methods=["POST"])
def scan_url():
    """
    Main URL security scanning endpoint.
    Expects JSON: { "url": "https://example.com" }
    or Form Data: url=https://example.com
    """
    if engine is None:
        return jsonify({"error": "NeuralPhish detection engine is unavailable."}), 500

    # Extract URL from JSON payload or form submission
    data = request.get_json(silent=True) or {}
    url = data.get("url") or request.form.get("url")

    if not url or not str(url).strip():
        return jsonify({
            "error": "Missing or empty URL. Please provide a valid URL string in 'url'."
        }), 400

    url = str(url).strip()

    try:
        analysis = engine.analyze(url)
        return jsonify({
            "success": True,
            "data": analysis
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Analysis failed: {str(e)}"
        }), 500


@app.route("/api/scan-message", methods=["POST"])
def scan_message():
    """
    Scans full email bodies, WhatsApp messages, SMS, or chat conversations.
    Extracts all URLs, verifies brand legitimacy, analyzes urgency/scam lures,
    and returns a comprehensive safety verdict with actionable advice.
    
    Expects JSON: { "message": "Urgent: Your Netflix account..." }
    or Form Data: message=Urgent: Your Netflix account...
    """
    if engine is None:
        return jsonify({"error": "NeuralPhish detection engine is unavailable."}), 500

    data = request.get_json(silent=True) or {}
    message_text = data.get("message") or request.form.get("message") or data.get("text") or request.form.get("text")

    if not message_text or not str(message_text).strip():
        return jsonify({
            "error": "Missing or empty message. Please provide the message text in 'message'."
        }), 400

    try:
        analysis = MessageScanner.analyze_message(str(message_text), engine)
        return jsonify({
            "success": True,
            "data": analysis
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Message analysis failed: {str(e)}"
        }), 500


@app.route("/api/scan-clipboard", methods=["GET", "POST"])
def scan_clipboard():
    """
    Scans the current clipboard contents on the host machine.
    Useful for local desktop integrations or quick-paste evaluations.
    """
    if engine is None:
        return jsonify({"error": "NeuralPhish detection engine is unavailable."}), 500

    text = None
    try:
        import pyperclip
        text = pyperclip.paste()
    except Exception:
        # Fallback to tkinter if pyperclip is not installed
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            text = root.clipboard_get()
            root.destroy()
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Clipboard access unavailable: {str(e)}"
            }), 500

    if not text or not str(text).strip():
        return jsonify({
            "success": True,
            "clipboard_empty": True,
            "message": "Clipboard is currently empty."
        }), 200

    try:
        analysis = MessageScanner.analyze_message(str(text), engine)
        return jsonify({
            "success": True,
            "clipboard_text_snippet": str(text)[:100] + ("..." if len(str(text)) > 100 else ""),
            "data": analysis
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Clipboard scan failed: {str(e)}"
        }), 500


@app.route("/api/batch-scan", methods=["POST"])
def batch_scan():
    """
    Batch URL scanning endpoint for security analysts / bulk audit.
    Expects JSON: { "urls": ["https://...", "http://..."] }
    """
    if engine is None:
        return jsonify({"error": "NeuralPhish detection engine is unavailable."}), 500

    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])

    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({
            "error": "Invalid request body. 'urls' must be a non-empty list of URL strings."
        }), 400

    if len(urls) > 50:
        return jsonify({
            "error": "Batch limit exceeded. Maximum 50 URLs allowed per batch request."
        }), 400

    results = engine.scan_batch(urls)
    
    # Calculate batch statistics
    dangerous_count = sum(1 for r in results if r["status"] == "danger")
    suspicious_count = sum(1 for r in results if r["status"] == "warning")
    safe_count = sum(1 for r in results if r["status"] in ("safe", "low_risk"))

    return jsonify({
        "success": True,
        "count": len(results),
        "summary": {
            "dangerous": dangerous_count,
            "suspicious": suspicious_count,
            "safe": safe_count,
        },
        "results": results
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    print(f"[*] Starting NeuralPhish Server on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)