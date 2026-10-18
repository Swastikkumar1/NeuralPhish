"""
NeuralPhish Desktop Messenger Guard
Background Sentinel that monitors the Windows clipboard for copied messages
from WhatsApp, Email, Telegram, SMS, or Browsers and immediately alerts the user
if a malicious or suspicious URL is detected.
"""

import argparse
import datetime
import hashlib
import os
import platform
import subprocess
import sys
import time
from typing import Optional

# Reconfigure stdout/stderr for Unicode support on Windows terminals
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure local imports work regardless of working directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from message_engine import MessageScanner
from scanner_engine import NeuralPhishEngine

try:
    import pyperclip
except ImportError:
    pyperclip = None

try:
    import winsound
except ImportError:
    winsound = None


class MessengerGuard:
    """
    Monitors system clipboard for copied text and links.
    When a user copies a WhatsApp message, email excerpt, or suspicious link,
    evaluates it in real-time and surfaces native Windows notifications.
    """

    def __init__(self, alert_log_file: Optional[str] = None):
        if alert_log_file is None:
            alert_log_file = os.path.join(SCRIPT_DIR, "threats_detected.log")
        self.alert_log_file = alert_log_file
        self.last_text_hash = ""
        self.engine = None
        self._init_engine()

    def _init_engine(self):
        print("[*] Initializing NeuralPhish Detection Engine...")
        try:
            self.engine = NeuralPhishEngine()
            print("[+] Engine successfully initialized.")
        except Exception as e:
            print(f"[!] Error initializing detection engine: {e}", file=sys.stderr)
            sys.exit(1)

    def get_clipboard(self) -> str:
        """Reads text from clipboard safely across methods."""
        if pyperclip is not None:
            try:
                return pyperclip.paste() or ""
            except Exception:
                pass

        # Windows PowerShell fallback if pyperclip is unavailable
        if platform.system() == "Windows":
            try:
                cmd = ["powershell", "-NoProfile", "-Command", "Get-Clipboard"]
                proc = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2
                )
                return proc.stdout.strip()
            except Exception:
                pass

        return ""

    def notify_windows(self, title: str, message: str, is_danger: bool = True):
        """Dispatches native Windows Toast notification or terminal alert."""
        # 1. Play alert chime
        if winsound is not None:
            try:
                sound_type = winsound.MB_ICONHAND if is_danger else winsound.MB_ICONEXCLAMATION
                winsound.MessageBeep(sound_type)
            except Exception:
                pass

        # 2. Native Windows Toast notification via PowerShell
        if platform.system() == "Windows":
            try:
                safe_title = title.replace('"', '`"').replace("'", "''")
                safe_msg = message.replace('"', '`"').replace("'", "''")
                ps_script = f"""
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                $textNodes = $template.GetElementsByTagName("text")
                $textNodes.Item(0).AppendChild($template.CreateTextNode("{safe_title}")) | Out-Null
                $textNodes.Item(1).AppendChild($template.CreateTextNode("{safe_msg}")) | Out-Null
                $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("NeuralPhish Security")
                $notification = [Windows.UI.Notifications.ToastNotification]::new($template)
                $notifier.Show($notification)
                """
                subprocess.Popen(
                    ["powershell", "-WindowStyle", "Hidden", "-NoProfile", "-Command", ps_script],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except Exception:
                pass

        # Console fallback
        print(f"\n[NOTIFICATION] {title}\n  -> {message}\n")

    def log_threat(self, result: dict, raw_text: str):
        """Appends threat diagnostic event to local log file."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        snippet = raw_text.replace("\n", " ")[:120]
        entry = (
            f"[{now}] VERDICT: {result['verdict']} | RISK: {result['risk_score']}/100\n"
            f"  Text: {snippet}\n"
            f"  Summary: {result['summary']}\n"
            f"  Extracted URLs: {result.get('extracted_urls', [])}\n"
            f"  Threats: {result['social_engineering'].get('urgency_triggers', [])}\n"
            f"  Brand Impersonation: {result['social_engineering'].get('has_brand_impersonation', False)}\n"
            f"{'-'*75}\n"
        )
        try:
            with open(self.alert_log_file, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception as e:
            print(f"[!] Could not write to threat log: {e}", file=sys.stderr)

    def scan_text(self, text: str, notify_safe: bool = False):
        """Analyzes string content and triggers alerts if malicious."""
        if not text or not text.strip():
            return None

        # Check if text contains URLs or high-risk scam lures before heavy NLP processing
        extracted = MessageScanner.extract_urls(text)
        has_lures = any(kw in text.lower() for kw in MessageScanner.URGENCY_KEYWORDS + MessageScanner.FINANCIAL_KEYWORDS)

        if not extracted and not has_lures:
            # Ordinary text copied by user (e.g. standard code or casual chat without links/scams)
            return None

        analysis = MessageScanner.analyze_message(text, self.engine)
        verdict = analysis["verdict"]
        risk_score = analysis["risk_score"]

        if verdict == "DANGEROUS":
            urls_str = ", ".join(analysis["extracted_urls"][:2])
            title = "🚨 NeuralPhish ALERT: Dangerous Phishing Detected!"
            body = (
                f"Risk: {risk_score}/100. DO NOT click or open link(s): {urls_str}. "
                f"Sender may be attempting to steal credentials."
            )
            print("\n" + "=" * 65)
            print("🚨 [ALERT] DANGEROUS PHISHING CONTENT DETECTED IN CLIPBOARD!")
            print(f"Risk Score : {risk_score}/100")
            print(f"Summary    : {analysis['summary']}")
            if analysis["extracted_urls"]:
                print(f"Links Found: {analysis['extracted_urls']}")
            if analysis["social_engineering"]["has_brand_impersonation"]:
                for flag in analysis["social_engineering"]["impersonation_flags"]:
                    print(f"WARNING    : {flag['warning']}")
            print("Action     : DO NOT CLICK. Block the sender.")
            print("=" * 65 + "\n")

            self.notify_windows(title, body, is_danger=True)
            self.log_threat(analysis, text)

        elif verdict == "SUSPICIOUS":
            urls_str = ", ".join(analysis["extracted_urls"][:2])
            title = "⚠️ NeuralPhish Warning: Suspicious Link/Message"
            body = f"Risk: {risk_score}/100. Potential threat detected: {urls_str}. Proceed with caution."
            print("\n" + "-" * 65)
            print("⚠️ [WARNING] SUSPICIOUS CONTENT DETECTED IN CLIPBOARD")
            print(f"Risk Score : {risk_score}/100")
            print(f"Summary    : {analysis['summary']}")
            if analysis["extracted_urls"]:
                print(f"Links Found: {analysis['extracted_urls']}")
            print("-" * 65 + "\n")

            self.notify_windows(title, body, is_danger=False)
            self.log_threat(analysis, text)

        elif notify_safe:
            title = "✅ NeuralPhish: Safe Link Verified"
            body = f"Link analyzed ({analysis.get('urls_found', 0)} links) - No threats detected."
            self.notify_windows(title, body, is_danger=False)

        return analysis

    def run_sentinel(self, interval: float = 1.0, notify_safe: bool = False):
        """
        Continuously polls clipboard for new content.
        Designed for background execution while chatting or reading emails.
        """
        print(f"\n=======================================================")
        print(f"  🛡️  NeuralPhish Messenger Guard is ACTIVE")
        print(f"  Monitoring clipboard for WhatsApp, Email & Chat threats...")
        print(f"  Copy any link or message (Ctrl+C) to scan automatically.")
        print(f"  Logs saved to: {self.alert_log_file}")
        print(f"  Press Ctrl+C to stop.")
        print(f"=======================================================\n")

        # Initial seed
        initial_text = self.get_clipboard()
        if initial_text:
            self.last_text_hash = hashlib.sha256(initial_text.encode("utf-8", "ignore")).hexdigest()

        try:
            while True:
                time.sleep(interval)
                current_text = self.get_clipboard()
                if not current_text or not current_text.strip():
                    continue

                text_hash = hashlib.sha256(current_text.encode("utf-8", "ignore")).hexdigest()
                if text_hash == self.last_text_hash:
                    # Content has not changed
                    continue

                self.last_text_hash = text_hash
                self.scan_text(current_text, notify_safe=notify_safe)

        except KeyboardInterrupt:
            print("\n[+] Messenger Guard stopped by user. Stay safe!")


def main():
    parser = argparse.ArgumentParser(
        description="NeuralPhish Desktop Messenger Guard: Real-time clipboard protection for WhatsApp & Email."
    )
    parser.add_argument(
        "--scan-now",
        action="store_true",
        help="Scan the current clipboard content once and exit.",
    )
    parser.add_argument(
        "--notify-safe",
        action="store_true",
        help="Also show desktop notification for clean/safe links (default: only alert on threats).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Clipboard polling interval in seconds (default: 1.0).",
    )
    args = parser.parse_args()

    guard = MessengerGuard()

    if args.scan_now:
        clip = guard.get_clipboard()
        if not clip:
            print("[-] Clipboard is currently empty.")
            return
        print(f"[*] Scanning current clipboard ({len(clip)} characters)...")
        res = guard.scan_text(clip, notify_safe=True)
        if res:
            print(f"[+] Result: {res['verdict']} (Risk: {res['risk_score']}/100)")
            print(f"[+] Summary: {res['summary']}")
        else:
            print("[+] No links or scam indicators in current clipboard.")
    else:
        guard.run_sentinel(interval=args.interval, notify_safe=args.notify_safe)


if __name__ == "__main__":
    main()
