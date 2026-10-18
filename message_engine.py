"""
NeuralPhish Message & Social Engineering Threat Analysis Engine
Extracts URLs and evaluates phishing lures from emails, WhatsApp messages,
SMS, Telegram, and chat messenger texts.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


class MessageScanner:
    """
    Analyzes unstructured message text from WhatsApp, Email, SMS, and chats.
    Extracts all standard, defanged, and schemeless links, detects social engineering
    psychological levers, and correlates brand mentions with destination domains.
    """

    # Major brands targeted by phishing and their official primary domain suffixes
    OFFICIAL_BRAND_DOMAINS: Dict[str, Set[str]] = {
        "whatsapp": {"whatsapp.com", "wa.me"},
        "netflix": {"netflix.com"},
        "paypal": {"paypal.com", "paypal.me"},
        "apple": {"apple.com", "icloud.com"},
        "amazon": {"amazon.com", "amzn.to", "amazon.in", "amazon.co.uk", "amazon.de"},
        "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
        "google": {"google.com", "gmail.com", "youtube.com", "goo.gl"},
        "facebook": {"facebook.com", "fb.com", "meta.com"},
        "instagram": {"instagram.com"},
        "telegram": {"telegram.org", "t.me"},
        "twitter": {"twitter.com", "x.com", "t.co"},
        "fedex": {"fedex.com"},
        "dhl": {"dhl.com"},
        "usps": {"usps.com"},
        "ups": {"ups.com"},
        "chase": {"chase.com"},
        "bank of america": {"bankofamerica.com", "bofa.com"},
        "wells fargo": {"wellsfargo.com"},
        "citi": {"citi.com", "citibank.com"},
        "sbi": {"onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"},
        "hdfc": {"hdfcbank.com"},
        "icici": {"icicibank.com"},
        "steam": {"steampowered.com", "steamcommunity.com"},
        "binance": {"binance.com"},
        "coinbase": {"coinbase.com"},
        "metamask": {"metamask.io"},
    }

    # Urgency & Coercion triggers
    URGENCY_KEYWORDS = [
        "urgent", "immediately", "within 24 hours", "24 hours", "suspended",
        "terminated", "blocked", "final notice", "action required", "locked",
        "unauthorized activity", "cancel your account", "deactivated",
        "act now", "limited time", "expires today", "emergency", "penalty",
        "legal action", "suspended account", "permanent closure", "warning"
    ]

    # Credential Harvesting & Security lures
    CREDENTIAL_KEYWORDS = [
        "verify your account", "confirm password", "update payment", "security alert",
        "unusual login", "one-time password", "otp", "2fa code", "reset password",
        "validate identity", "kyc update", "kyc verification", "unlock account",
        "billing information", "confirm details", "login to secure"
    ]

    # Financial & Prize Scams
    FINANCIAL_KEYWORDS = [
        "lottery", "won", "winner", "prize", "cash reward", "refund approved",
        "invoice attached", "unpaid invoice", "tax refund", "wire transfer",
        "crypto giveaway", "free gift", "claim reward", "inheritance",
        "customs fee", "settlement", "bonus deposit"
    ]

    @classmethod
    def normalize_defanged(cls, text: str) -> str:
        """Restores defanged URLs (e.g. hxxps://site[.]com) to standard format."""
        if not text:
            return ""
        t = text
        t = re.sub(r"\[\.\]|\(dot\)|\[dot\]", ".", t, flags=re.IGNORECASE)
        t = re.sub(r"\[/\]|\[slash\]", "/", t, flags=re.IGNORECASE)
        t = re.sub(r"hxxp(s)?://", r"http\1://", t, flags=re.IGNORECASE)
        t = re.sub(r"h\*\*p(s)?://", r"http\1://", t, flags=re.IGNORECASE)
        return t

    @classmethod
    def extract_urls(cls, text: str) -> List[str]:
        """
        Extracts all standard, defanged, and schemeless URLs from arbitrary message text.
        Strips surrounding punctuation and deduplicates.
        """
        if not text or not str(text).strip():
            return []

        cleaned_text = cls.normalize_defanged(str(text))

        # 1. Markdown style: [Click here](https://evil.com)
        md_urls = re.findall(r"\[.*?\]\((https?://[^\s\)]+)\)", cleaned_text)

        # 2. HTML style: <a href="https://evil.com">
        html_urls = re.findall(
            r"<a\s+(?:[^>]*?\s+)?href=[\'\"](https?://[^\'\"]+)[\'\"]",
            cleaned_text,
            flags=re.IGNORECASE,
        )

        # 3. Standard protocol URLs: https://... or http://...
        std_urls = re.findall(r"https?://[^\s<>\"\'\)]+", cleaned_text)

        # 4. Schemeless domain patterns (e.g. www.fake.com/login or bit.ly/xyz or target.xyz/auth)
        schemeless_pattern = (
            r"(?:^|[\s(])((?:www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|"
            r"[a-zA-Z0-9.-]+\.(?:com|org|net|xyz|top|info|biz|ru|cn|online|"
            r"site|app|cc|co|io|me|tk|ml|ga|cf|gq|live|shop|club|vip|icu|pro|"
            r"work|buzz|click|rest|cam|country|stream|download|ly|to|link|dev|"
            r"ai|page|in|uk|de|ca))"
            r"(?:/[^\s<>\"\'\)]*)?)"
        )
        schemeless = re.findall(schemeless_pattern, cleaned_text)

        results: List[str] = []
        seen: Set[str] = set()

        def add_clean_url(u: str):
            # Clean trailing sentence punctuation commonly attached to URLs
            cleaned = u.strip().rstrip(".,;:!?)>]}'")
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                results.append(cleaned)

        for u in md_urls + html_urls + std_urls:
            add_clean_url(u)

        for raw_domain in schemeless:
            clean_dom = raw_domain.strip().rstrip(".,;:!?)>]}'")
            if clean_dom:
                cand = (
                    "https://" + clean_dom
                    if not clean_dom.startswith(("http://", "https://"))
                    else clean_dom
                )
                # Check if this domain is already covered by a full URL
                if not any(clean_dom in s for s in seen):
                    seen.add(cand)
                    results.append(cand)

        return results

    @classmethod
    def get_primary_domain(cls, url: str) -> str:
        """Extracts primary registered domain (e.g. sub.domain.com -> domain.com)."""
        has_scheme = bool(re.match(r"^[a-zA-Z]+://", url))
        url_to_parse = url if has_scheme else "http://" + url
        try:
            parsed = urlparse(url_to_parse)
            netloc = parsed.netloc.lower().split(":")[0]
            parts = netloc.split(".")
            if len(parts) >= 2:
                return f"{parts[-2]}.{parts[-1]}"
            return netloc
        except Exception:
            return ""

    @classmethod
    def analyze_social_engineering(cls, text: str, urls: List[str]) -> Dict[str, Any]:
        """
        Analyzes psychological manipulation patterns and verifies whether
        mentioned brands match the actual destination domains.
        """
        text_lower = text.lower()

        # Urgency detection
        found_urgency = [kw for kw in cls.URGENCY_KEYWORDS if kw in text_lower]

        # Credential lures detection
        found_credential = [kw for kw in cls.CREDENTIAL_KEYWORDS if kw in text_lower]

        # Financial lures detection
        found_financial = [kw for kw in cls.FINANCIAL_KEYWORDS if kw in text_lower]

        # Brand Mention vs URL Domain Verification (Brand Impersonation Detection)
        impersonation_flags: List[Dict[str, Any]] = []
        extracted_domains = [cls.get_primary_domain(u) for u in urls]

        for brand, official_domains in cls.OFFICIAL_BRAND_DOMAINS.items():
            # Check if brand is referenced in the message
            # Use word boundaries so "bank" doesn't match inside other words
            pattern = rf"\b{re.escape(brand)}\b"
            if re.search(pattern, text_lower):
                # Brand is mentioned! Now check if any extracted URL actually matches an official domain
                if urls:
                    has_official_match = False
                    mismatched_urls = []
                    for u, dom in zip(urls, extracted_domains):
                        is_match = any(
                            dom == off_dom or dom.endswith("." + off_dom)
                            for off_dom in official_domains
                        )
                        if is_match:
                            has_official_match = True
                        else:
                            mismatched_urls.append(u)

                    if not has_official_match and mismatched_urls:
                        impersonation_flags.append({
                            "brand": brand.title(),
                            "official_domains": list(official_domains),
                            "mismatched_urls": mismatched_urls,
                            "warning": (
                                f"Message claims to be from {brand.title()}, but the destination "
                                f"link ({mismatched_urls[0]}) does NOT match any official {brand.title()} domain."
                            ),
                        })

        urgency_score = min(30.0, len(found_urgency) * 10.0)
        credential_score = min(25.0, len(found_credential) * 10.0)
        financial_score = min(20.0, len(found_financial) * 8.0)
        impersonation_score = 35.0 if impersonation_flags else 0.0

        social_risk_score = round(
            min(100.0, urgency_score + credential_score + financial_score + impersonation_score),
            1,
        )

        return {
            "urgency_triggers": found_urgency,
            "credential_lures": found_credential,
            "financial_lures": found_financial,
            "impersonation_flags": impersonation_flags,
            "social_risk_score": social_risk_score,
            "has_brand_impersonation": len(impersonation_flags) > 0,
            "threat_level": (
                "HIGH" if social_risk_score >= 50 else ("MEDIUM" if social_risk_score >= 20 else "LOW")
            ),
        }

    @classmethod
    def analyze_message(cls, text: str, engine: Any) -> Dict[str, Any]:
        """
        Complete end-to-end evaluation of an email, WhatsApp message, or SMS.
        Integrates:
        1. URL Extraction
        2. Individual URL scanning via NeuralPhish ML + Lexical Engine
        3. Social engineering & brand impersonation correlation
        4. Consolidated Threat Verdict & Recommendations for end users
        """
        raw_text = str(text or "").strip()
        if not raw_text:
            return {
                "verdict": "CLEAN",
                "status": "safe",
                "risk_score": 0.0,
                "summary": "No text provided for analysis.",
                "urls_found": 0,
                "url_results": [],
                "social_engineering": {},
                "recommendations": ["No content to review."],
            }

        extracted_urls = cls.extract_urls(raw_text)
        social_analysis = cls.analyze_social_engineering(raw_text, extracted_urls)

        # Case 1: No URLs in message
        if not extracted_urls:
            has_scam_signals = (
                social_analysis["urgency_triggers"]
                or social_analysis["credential_lures"]
                or social_analysis["financial_lures"]
            )
            if has_scam_signals:
                verdict = "SUSPICIOUS"
                status = "warning"
                risk_score = min(50.0, social_analysis["social_risk_score"])
                summary = (
                    "No links were found in this message, but it exhibits strong psychological "
                    "pressure (urgency / scam keywords). Be vigilant if the sender asks for money, OTPs, or sends a link later."
                )
                recommendations = [
                    "Do NOT share OTPs, passwords, or personal banking details over chat.",
                    "Verify the sender's identity through another trusted communication channel.",
                    "If they ask you to send money or download an attachment, verify independently.",
                ]
            else:
                verdict = "SAFE"
                status = "safe"
                risk_score = 0.0
                summary = "No links or high-risk social engineering patterns were detected in this message."
                recommendations = ["The message appears harmless. Standard communication etiquette applies."]

            return {
                "verdict": verdict,
                "status": status,
                "risk_score": risk_score,
                "summary": summary,
                "urls_found": 0,
                "url_results": [],
                "social_engineering": social_analysis,
                "recommendations": recommendations,
            }

        # Case 2: URLs detected — analyze each URL through NeuralPhishEngine
        url_results: List[Dict[str, Any]] = []
        max_url_risk = 0.0
        dangerous_urls_count = 0
        suspicious_urls_count = 0

        for u in extracted_urls:
            try:
                analysis = engine.analyze(u)
                url_results.append(analysis)
                score = analysis.get("risk_score", 0.0)
                max_url_risk = max(max_url_risk, score)
                if analysis.get("status") == "danger":
                    dangerous_urls_count += 1
                elif analysis.get("status") == "warning":
                    suspicious_urls_count += 1
            except Exception as e:
                # Fallback if single analysis fails
                url_results.append({
                    "url": u,
                    "verdict": "SUSPICIOUS",
                    "status": "warning",
                    "risk_score": 50.0,
                    "summary": f"Could not complete full scan: {str(e)}",
                    "threat_indicators": ["Scan evaluation anomaly"],
                })
                suspicious_urls_count += 1
                max_url_risk = max(max_url_risk, 50.0)

        # Composite Message Risk Score
        # URL threat takes 70% priority, social engineering & impersonation takes 30%
        base_risk = max_url_risk
        if social_analysis["has_brand_impersonation"]:
            base_risk = max(base_risk, 85.0)  # Impersonation is severe
        elif social_analysis["social_risk_score"] > 30:
            base_risk = min(100.0, base_risk + (social_analysis["social_risk_score"] * 0.25))

        final_risk = round(min(100.0, base_risk), 1)

        # Determine overall message verdict
        if dangerous_urls_count > 0 or social_analysis["has_brand_impersonation"] or final_risk >= 70.0:
            verdict = "DANGEROUS"
            status = "danger"
            summary = (
                f"🚨 Phishing / Scam Alert: Detected {len(extracted_urls)} link(s) in this message. "
                f"High-risk threat indicators confirm this is a malicious attempt to deceive you."
            )
            recommendations = [
                "⛔ DO NOT CLICK or tap any of the links in this message.",
                "🚫 Never submit passwords, credit card numbers, or OTPs on links sent via chat.",
                "🛡️ Block and report the sender on WhatsApp, email, or your messaging app immediately.",
                "⚠️ If you already entered credentials, immediately change your password on the official website.",
            ]
        elif suspicious_urls_count > 0 or final_risk >= 40.0:
            verdict = "SUSPICIOUS"
            status = "warning"
            summary = (
                f"⚠️ Suspicious Message: Found {len(extracted_urls)} link(s) with warning signs "
                f"or deceptive messaging patterns. Exercise extreme caution."
            )
            recommendations = [
                "Proceed with caution. Do not click until you have verified the sender.",
                "Instead of clicking the link, navigate to the organization's official website directly.",
                "Check the sender's phone number or email address carefully for subtle misspellings.",
            ]
        else:
            verdict = "SAFE"
            status = "safe"
            summary = (
                f"✅ Legitimate Profile: Analyzed {len(extracted_urls)} link(s). "
                f"No malicious phishing markers or fraudulent lures were identified."
            )
            recommendations = [
                "Links appear benign and match standard reputable domain structures.",
                "Always ensure your browser shows a secure lock icon when entering any sensitive information.",
            ]

        return {
            "verdict": verdict,
            "status": status,
            "risk_score": final_risk,
            "summary": summary,
            "urls_found": len(extracted_urls),
            "extracted_urls": extracted_urls,
            "dangerous_count": dangerous_urls_count,
            "suspicious_count": suspicious_urls_count,
            "url_results": url_results,
            "social_engineering": social_analysis,
            "recommendations": recommendations,
        }
