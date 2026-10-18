"""
NeuralPhish Command Line Interface (CLI)
Instant terminal scanning for suspicious URLs, emails, and WhatsApp messages.
"""

import argparse
import json
import os
import sys

# Configure UTF-8 for Windows console
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from scanner_engine import NeuralPhishEngine
from message_engine import MessageScanner


def format_badge(status: str, verdict: str) -> str:
    color_map = {
        "DANGEROUS": "\033[91m[DANGEROUS]\033[0m",
        "SUSPICIOUS": "\033[93m[SUSPICIOUS]\033[0m",
        "LOW RISK": "\033[96m[LOW RISK]\033[0m",
        "SAFE": "\033[92m[SAFE]\033[0m",
        "CLEAN": "\033[92m[CLEAN]\033[0m",
    }
    return color_map.get(verdict, f"[{verdict}]")


def print_banner():
    banner = r"""
 _   _                      _ _____  _     _     _     
| \ | |                    | |  __ \| |   (_)   | |    
|  \| | ___ _   _ _ __ __ _| | |__) | |__  _ ___| |__  
| . ` |/ _ \ | | | '__/ _` | |  ___/| '_ \| / __| '_ \ 
| |\  |  __/ |_| | | | (_| | | |    | | | | \__ \ | | |
|_| \_|\___|\__,_|_|  \__,_|_|_|    |_| |_|_|___/_| |_|
        Neural Hybrid Phishing & Messenger Shield
"""
    print(banner)


def scan_single_url(engine: NeuralPhishEngine, url: str, as_json: bool = False):
    res = engine.analyze(url)
    if as_json:
        print(json.dumps(res, indent=2))
        return

    print("=" * 65)
    print(f"URL           : {res['url']}")
    print(f"VERDICT       : {format_badge(res['status'], res['verdict'])}")
    print(f"RISK SCORE    : {res['risk_score']} / 100")
    print(f"ML CONFIDENCE : {res['ml_analysis']['confidence_score']}% ({res['ml_analysis']['classification']})")
    print(f"SUMMARY       : {res['summary']}")
    
    if res["threat_indicators"]:
        print("\n[Threat Indicators]")
        for ti in res["threat_indicators"]:
            print(f"  • {ti}")
            
    print("=" * 65)


def scan_message_text(engine: NeuralPhishEngine, text: str, as_json: bool = False):
    res = MessageScanner.analyze_message(text, engine)
    if as_json:
        print(json.dumps(res, indent=2))
        return

    print("=" * 65)
    print(f"MESSAGE VERDICT : {format_badge(res['status'], res['verdict'])}")
    print(f"RISK SCORE      : {res['risk_score']} / 100")
    print(f"SUMMARY         : {res['summary']}")
    print(f"LINKS DETECTED  : {res['urls_found']}")

    if res["extracted_urls"]:
        print("\n[Extracted Links]")
        for u in res["extracted_urls"]:
            print(f"  🔗 {u}")

    soc = res["social_engineering"]
    if soc.get("has_brand_impersonation"):
        print("\n🚨 [BRAND IMPERSONATION DETECTED]")
        for flag in soc["impersonation_flags"]:
            print(f"  ⚠️ {flag['warning']}")

    if soc.get("urgency_triggers"):
        print(f"\n[Urgency Triggers] : {', '.join(soc['urgency_triggers'])}")

    if soc.get("financial_lures"):
        print(f"[Financial Lures]  : {', '.join(soc['financial_lures'])}")

    print("\n[Action Guidance]")
    for rec in res["recommendations"]:
        print(f"  {rec}")

    print("=" * 65)


def interactive_mode(engine: NeuralPhishEngine):
    print_banner()
    print("Interactive Mode Active.")
    print("Type or paste any URL, WhatsApp chat, or email message below.")
    print("Type 'exit' or 'quit' to close.\n")

    while True:
        try:
            line = input("\nNeuralPhish> ").strip()
            if not line:
                continue
            if line.lower() in ("exit", "quit", "q"):
                print("Exiting NeuralPhish. Stay safe!")
                break

            # If it's a pure URL without spaces
            if " " not in line and ("." in line or "://" in line):
                scan_single_url(engine, line)
            else:
                scan_message_text(engine, line)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting. Stay safe!")
            break


def main():
    parser = argparse.ArgumentParser(
        description="NeuralPhish: Enterprise Phishing & Messenger Threat Scanner."
    )
    parser.add_argument("target", nargs="?", help="URL or message text to scan.")
    parser.add_argument("--message", "-m", help="Explicitly scan unstructured message text.")
    parser.add_argument("--url", "-u", help="Explicitly scan a single URL.")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive prompt.")
    parser.add_argument("--json", action="store_true", help="Output raw JSON analysis.")
    args = parser.parse_args()

    engine = NeuralPhishEngine()

    if args.interactive or (not args.target and not args.message and not args.url):
        interactive_mode(engine)
        return

    if args.message:
        scan_message_text(engine, args.message, as_json=args.json)
    elif args.url:
        scan_single_url(engine, args.url, as_json=args.json)
    elif args.target:
        if " " not in args.target and ("." in args.target or "://" in args.target):
            scan_single_url(engine, args.target, as_json=args.json)
        else:
            scan_message_text(engine, args.target, as_json=args.json)


if __name__ == "__main__":
    main()
