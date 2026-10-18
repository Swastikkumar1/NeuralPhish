"""
NeuralPhish Hybrid Detection Engine
Combines NLP-based Machine Learning inference with Lexical & Cybersecurity Heuristics
for enterprise-grade Phishing URL Detection.
"""

import math
import os
import pickle
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from nltk.stem.snowball import SnowballStemmer
from nltk.tokenize import RegexpTokenizer


class NeuralPhishEngine:
    """
    Hybrid Phishing Detection Engine.
    Integrates trained NLP models (MultinomialNB / CountVectorizer) with
    cybersecurity heuristics including Shannon Entropy, IP host detection,
    typosquatting indicators, and suspicious TLD scoring.
    """

    # Suspicious keywords frequently observed in phishing / credential harvesting
    SUSPICIOUS_KEYWORDS = {
        "login", "signin", "verify", "verification", "security", "secure",
        "account", "update", "banking", "authenticate", "confirm", "password",
        "credential", "wallet", "support", "billing", "recover", "unlock",
        "suspension", "paypal", "apple", "microsoft", "amazon", "netflix",
        "ebay", "wellsfargo", "chase", "citi", "bankofamerica"
    }

    # High-risk Top Level Domains commonly leveraged for disposable phishing attacks
    SUSPICIOUS_TLDS = {
        "xyz", "top", "work", "buzz", "click", "fit", "gq", "cf", "ga",
        "ml", "tk", "rest", "cam", "country", "stream", "download", "racing"
    }

    # Trusted high-reputation domains for baseline comparison
    SAFE_DOMAINS = {
        "google.com", "github.com", "microsoft.com", "apple.com",
        "wikipedia.org", "amazon.com", "youtube.com", "linkedin.com",
        "twitter.com", "x.com", "stackoverflow.com", "python.org"
    }

    # Popular URL Shorteners that conceal the actual destination
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorte.st"
    }

    def __init__(self, model_path: Optional[str] = None, vectorizer_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Resolve model path (handling phising.pkl vs phishing.pkl naming)
        if model_path is None:
            candidates = ["phising.pkl", "phishing.pkl", "phising_mnb.pkl"]
            for cand in candidates:
                p = os.path.join(base_dir, cand)
                if os.path.exists(p):
                    model_path = p
                    break
        
        if vectorizer_path is None:
            vectorizer_path = os.path.join(base_dir, "vectorizer.pkl")

        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        
        # NLP Preprocessing components matching the training pipeline
        self.tokenizer = RegexpTokenizer(r"[A-Za-z]+")
        self.stemmer = SnowballStemmer("english")

        # Load models
        self.model = None
        self.vectorizer = None
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads serialized model and vectorizer pickles."""
        if self.model_path and os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)
        else:
            raise FileNotFoundError(f"Model file not found. Checked: {self.model_path}")

        if self.vectorizer_path and os.path.exists(self.vectorizer_path):
            with open(self.vectorizer_path, "rb") as f:
                self.vectorizer = pickle.load(f)
        else:
            raise FileNotFoundError(f"Vectorizer file not found: {self.vectorizer_path}")

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Calculates Shannon Entropy of a string.
        High entropy in domain names often indicates Domain Generation Algorithms (DGA)
        or random string obfuscation.
        """
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts: Dict[str, int] = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def extract_lexical_features(self, url: str) -> Dict[str, Any]:
        """
        Parses URL and performs exhaustive lexical and security checks.
        """
        # Ensure scheme for urllib parsing
        has_scheme = bool(re.match(r"^[a-zA-Z]+://", url))
        url_to_parse = url if has_scheme else "http://" + url
        parsed = urlparse(url_to_parse)

        protocol = parsed.scheme.lower() if has_scheme else "not_specified"
        is_https = (protocol == "https")
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

        # Strip standard port if present for host checks
        host_no_port = netloc.split(":")[0]

        # Host type: Check if hostname is an IPv4 or IPv6 address
        is_ip_address = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host_no_port))
        
        # Punycode / IDN Homoglyph detection
        is_punycode = "xn--" in netloc

        # Subdomain analysis
        domain_parts = host_no_port.split(".")
        tld = domain_parts[-1] if len(domain_parts) > 1 else ""
        
        if len(domain_parts) > 2:
            subdomain = ".".join(domain_parts[:-2])
            primary_domain = f"{domain_parts[-2]}.{domain_parts[-1]}"
        elif len(domain_parts) == 2:
            subdomain = ""
            primary_domain = host_no_port
        else:
            subdomain = ""
            primary_domain = host_no_port

        subdomain_count = len(subdomain.split(".")) if subdomain else 0
        
        # Shannon Entropy on domain and full URL
        domain_entropy = self.calculate_shannon_entropy(host_no_port)
        url_entropy = self.calculate_shannon_entropy(url)

        # Keyword inspection across domain and path
        full_lower = url.lower()
        flagged_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in full_lower]

        # URL Shortener detection
        is_shortener = host_no_port in self.URL_SHORTENERS

        # Suspicious TLD check
        is_suspicious_tld = tld in self.SUSPICIOUS_TLDS

        # Structural flags
        has_at_symbol = "@" in url
        has_double_slash_redirect = "//" in path
        has_non_standard_port = bool(parsed.port and parsed.port not in (80, 443))
        is_abnormally_long = len(url) > 75

        # Whitelist check
        is_known_safe = primary_domain in self.SAFE_DOMAINS

        return {
            "protocol": protocol,
            "is_https": is_https,
            "netloc": netloc,
            "primary_domain": primary_domain,
            "subdomain": subdomain,
            "subdomain_count": subdomain_count,
            "tld": tld,
            "path": path,
            "query": query,
            "is_ip_address": is_ip_address,
            "is_punycode": is_punycode,
            "domain_entropy": domain_entropy,
            "url_entropy": url_entropy,
            "flagged_keywords": flagged_keywords,
            "is_shortener": is_shortener,
            "is_suspicious_tld": is_suspicious_tld,
            "has_at_symbol": has_at_symbol,
            "has_double_slash_redirect": has_double_slash_redirect,
            "has_non_standard_port": has_non_standard_port,
            "is_abnormally_long": is_abnormally_long,
            "url_length": len(url),
            "is_known_safe": is_known_safe,
        }

    def predict_ml(self, url: str) -> Dict[str, Any]:
        """
        Runs NLP tokenization, stemming, vectorization, and model inference.
        Normalizes by stripping protocol/www to prevent dataset bias.
        """
        # Strip protocol and www prefix to prevent spurious correlation
        cleaned_url = re.sub(r"^https?://(www\.)?", "", url.strip())

        # Tokenize using RegexpTokenizer([A-Za-z]+)
        raw_tokens = self.tokenizer.tokenize(cleaned_url)

        # Apply Snowball stemmer (matches training pipeline)
        stemmed_tokens = [self.stemmer.stem(token) for token in raw_tokens]
        stemmed_text = " ".join(stemmed_tokens)

        # Transform using fitted CountVectorizer
        features = self.vectorizer.transform([stemmed_text])

        # Inference
        prediction = self.model.predict(features)[0]
        
        # Probability calculation
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(features)[0]
            # Classes are ['bad', 'good']
            bad_idx = list(self.model.classes_).index("bad") if "bad" in self.model.classes_ else 0
            good_idx = list(self.model.classes_).index("good") if "good" in self.model.classes_ else 1
            bad_prob = float(probs[bad_idx])
            good_prob = float(probs[good_idx])
        else:
            bad_prob = 1.0 if prediction == "bad" else 0.0
            good_prob = 1.0 - bad_prob

        # Explainable AI (XAI): Compute token-level log-odds feature attribution
        # log_odds = log P(w | bad) - log P(w | good)
        token_attributions = []
        if hasattr(self.model, "feature_log_prob_") and hasattr(self.vectorizer, "vocabulary_"):
            classes = list(self.model.classes_)
            if "bad" in classes and "good" in classes:
                bad_idx = classes.index("bad")
                good_idx = classes.index("good")
                for tok in set(stemmed_tokens):
                    idx = self.vectorizer.vocabulary_.get(tok)
                    if idx is not None:
                        log_bad = self.model.feature_log_prob_[bad_idx][idx]
                        log_good = self.model.feature_log_prob_[good_idx][idx]
                        log_odds = round(float(log_bad - log_good), 3)
                        token_attributions.append({
                            "token": tok,
                            "log_odds": log_odds,
                            "indicates": "phishing" if log_odds > 0 else "legitimate"
                        })
                token_attributions.sort(key=lambda x: x["log_odds"], reverse=True)

        return {
            "raw_prediction": prediction,
            "malicious_probability": round(bad_prob, 4),
            "benign_probability": round(good_prob, 4),
            "stemmed_tokens": stemmed_tokens[:15],
            "total_tokens_extracted": len(stemmed_tokens),
            "token_attributions": token_attributions[:10],
            "top_malicious_tokens": [t["token"] for t in token_attributions if t["log_odds"] > 1.5][:5],
        }

    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Complete Hybrid Threat Evaluation combining ML inference and Lexical Heuristics.
        Returns a rich diagnostic report suitable for interactive UI and REST API.
        """
        url = url.strip()
        if not url:
            raise ValueError("URL cannot be empty")

        lexical = self.extract_lexical_features(url)
        ml_result = self.predict_ml(url)

        # --- Compute Composite Risk Score (0 - 100) ---
        # Base score from ML malicious probability (0 - 70 points)
        ml_score = ml_result["malicious_probability"] * 70.0
        heuristic_score = 0.0
        threat_indicators: List[str] = []

        # Heuristic Risk Factors
        if lexical["is_ip_address"]:
            heuristic_score += 20.0
            threat_indicators.append("Host is an explicit IP address rather than a domain name")

        if lexical["is_punycode"]:
            heuristic_score += 15.0
            threat_indicators.append("Punycode detected (potential IDN homograph attack)")

        if lexical["has_at_symbol"]:
            heuristic_score += 20.0
            threat_indicators.append("Contains '@' symbol (credential manipulation / deception)")

        if lexical["has_non_standard_port"]:
            heuristic_score += 10.0
            threat_indicators.append("Non-standard web port detected")

        if lexical["is_shortener"]:
            heuristic_score += 10.0
            threat_indicators.append("Known URL shortener concealing actual destination")

        if lexical["is_suspicious_tld"]:
            heuristic_score += 12.0
            threat_indicators.append(f"High-risk Top-Level Domain (.{lexical['tld']}) commonly used in phishing")

        if not lexical["is_https"]:
            heuristic_score += 8.0
            threat_indicators.append("No SSL/HTTPS encryption (unsecured plaintext HTTP)")

        if lexical["subdomain_count"] >= 3:
            heuristic_score += 8.0
            threat_indicators.append(f"Excessive subdomain depth ({lexical['subdomain_count']} levels)")

        if lexical["domain_entropy"] > 4.2:
            heuristic_score += 10.0
            threat_indicators.append(f"Elevated domain entropy ({lexical['domain_entropy']}) indicates algorithmic randomness (DGA)")

        if len(lexical["flagged_keywords"]) >= 2:
            heuristic_score += 12.0
            threat_indicators.append(f"Multiple security/credential keywords found: {', '.join(lexical['flagged_keywords'][:4])}")
        elif len(lexical["flagged_keywords"]) == 1:
            heuristic_score += 5.0
            threat_indicators.append(f"Security/credential keyword found: {lexical['flagged_keywords'][0]}")

        if lexical["is_abnormally_long"]:
            heuristic_score += 5.0
            threat_indicators.append(f"Unusually long URL length ({lexical['url_length']} characters)")

        # Whitelist mitigation: Known safe domains reduce heuristic penalty if ML is also benign
        if lexical["is_known_safe"] and ml_result["benign_probability"] > 0.6:
            heuristic_score = max(0.0, heuristic_score - 20.0)
            ml_score = min(ml_score, 10.0)

        # Calculate final composite risk score (0 - 100)
        total_risk = min(100.0, round(ml_score + heuristic_score, 1))

        # Categorize verdict & severity
        if total_risk >= 70.0:
            verdict = "DANGEROUS"
            status = "danger"
            summary = "High probability of Phishing or Malicious Activity. Do not navigate to or enter credentials on this site."
        elif total_risk >= 45.0:
            verdict = "SUSPICIOUS"
            status = "warning"
            summary = "Suspicious threat signals detected. Verify link source and proceed with heightened caution."
        elif total_risk >= 20.0:
            verdict = "LOW RISK"
            status = "low_risk"
            summary = "Minor security anomalies observed, but no conclusive malicious indicators found."
        else:
            verdict = "SAFE"
            status = "safe"
            summary = "Legitimate URL profile. Standard benign patterns verified by neural and heuristic analysis."

        return {
            "url": url,
            "verdict": verdict,
            "status": status,
            "risk_score": total_risk,
            "summary": summary,
            "threat_indicators": threat_indicators,
            "ml_analysis": {
                "classification": "Phishing (Bad)" if ml_result["raw_prediction"] == "bad" else "Legitimate (Good)",
                "confidence_score": round(max(ml_result["malicious_probability"], ml_result["benign_probability"]) * 100, 1),
                "malicious_probability_pct": round(ml_result["malicious_probability"] * 100, 1),
                "benign_probability_pct": round(ml_result["benign_probability"] * 100, 1),
                "tokens_analyzed": ml_result["stemmed_tokens"],
                "token_attributions": ml_result.get("token_attributions", []),
                "top_malicious_tokens": ml_result.get("top_malicious_tokens", []),
            },
            "lexical_breakdown": {
                "protocol": lexical["protocol"],
                "is_https": lexical["is_https"],
                "primary_domain": lexical["primary_domain"],
                "subdomain": lexical["subdomain"] or "None",
                "tld": lexical["tld"],
                "path": lexical["path"] or "/",
                "domain_entropy": lexical["domain_entropy"],
                "is_ip_host": lexical["is_ip_address"],
                "is_punycode": lexical["is_punycode"],
                "url_length": lexical["url_length"],
                "flagged_keywords": lexical["flagged_keywords"],
            },
        }

    def scan_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scans a collection of URLs and returns bulk diagnostic summaries."""
        results = []
        for raw_url in urls:
            raw_url = raw_url.strip()
            if not raw_url:
                continue
            try:
                res = self.analyze(raw_url)
                results.append({
                    "url": raw_url,
                    "verdict": res["verdict"],
                    "status": res["status"],
                    "risk_score": res["risk_score"],
                    "ml_confidence": res["ml_analysis"]["confidence_score"],
                    "summary": res["summary"],
                })
            except Exception as e:
                results.append({
                    "url": raw_url,
                    "verdict": "ERROR",
                    "status": "danger",
                    "risk_score": 100.0,
                    "ml_confidence": 0.0,
                    "summary": f"Failed to analyze: {str(e)}",
                })
        return results
