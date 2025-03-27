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
import socks
import socket as sock

# Setup anonymous logging
log_file = "venom_anonymous.log"
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m',  # Blue
        'INFO': '\033[92m',   # Green
        'WARNING': '\033[93m', # Yellow
        'ERROR': '\033[91m',  # Red
        'RESET': '\033[0m'
    }
    def format(self, record):
        log_msg = super().format(record)
        return f"{self.COLORS.get(record.levelname, self.COLORS['RESET'])}{log_msg}{self.COLORS['RESET']}"

logging.basicConfig(
    level=logging.DEBUG if '--verbose' in sys.argv else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(log_file, mode='a', encoding='utf-8')]
)
for handler in logging.getLogger().handlers:
    if isinstance(handler, logging.StreamHandler):
        handler.setFormatter(ColoredFormatter())
logging.info("Logging initialized anonymously")

# Colors for terminal
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
{BLUE}║{RESET}                            {WHITE}Version 5.46{RESET}                            {BLUE}║{RESET}
{BLUE}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        f"{WHITE}{BOLD}Advanced XSS detection with precise context analysis{RESET}",
        f"{WHITE}{BOLD}Parallel payload testing with adaptive throttling{RESET}",
        f"{WHITE}{BOLD}Robust execution verification with multi-context testing{RESET}",
        f"{WHITE}{BOLD}WAF/IPS evasion with dynamic bypass payloads{RESET}",
        f"{WHITE}{BOLD}Custom payload integration from directory or file{RESET}",
        f"{WHITE}{BOLD}AI-driven payload optimization with ML weighting{RESET}",
        f"{WHITE}{BOLD}Detailed reporting with full URLs and payloads{RESET}",
        f"{WHITE}{BOLD}Anonymous operation mode for privacy{RESET}"
    ]
    return banner + "\n".join(f"{GREEN}●{RESET} {feature}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a tool for ethical penetration testers to detect XSS vulnerabilities anonymously. Version 5.46 ensures no traceable user data is exposed.

Usage:
  python3 venom.py <url> --scan-xss [options]

Examples:
  python3 venom.py http://target.com --scan-xss --anonymous --use-tor -w 5 --verify-execution
    - Anonymous scan with Tor and execution verification.
  python3 venom.py http://example.com --scan-xss --stealth --use-403-bypass --export-report report.json
    - Stealth mode with 403 bypass and JSON export.
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan (e.g., http://target.com).")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of concurrent threads (default: 5, max: 20).")
    parser.add_argument("--ai-assist", action="store_true", help="Enable AI-driven payload optimization.")
    parser.add_argument("--ai-key", type=str, help="API key for external AI platform (optional).")
    parser.add_argument("--ai-platform", type=str, choices=['xai-grok', 'openai-gpt3', 'google-gemini'],
                        help="External AI platform (requires --ai-key).")
    parser.add_argument("--scan-xss", action="store_true", help="Enable XSS scanning (required).", required=True)
    parser.add_argument("--payloads-dir", default="/tmp/payloads/", help="Directory with custom payload files.")
    parser.add_argument("--payload-file", type=str, help="Specific payload file to use.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP request timeout in seconds (default: 30).")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed logging (use cautiously).")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode: 2 workers, 5-15s delays.")
    parser.add_argument("--min-delay", type=float, help="Min delay between requests (default: 0.1 or 5 in stealth).")
    parser.add_argument("--max-delay", type=float, help="Max delay between requests (default: 0.5 or 15 in stealth).")
    parser.add_argument("--full-report", action="store_true", help="Show detailed vulnerabilities in report.")
    parser.add_argument("--export-report", type=str, help="Export report to a file (e.g., report.json, report.csv).")
    parser.add_argument("-H", "--headers", action='append', default=[], help="Custom headers (e.g., 'Cookie: session=abc123').")
    parser.add_argument("--method", choices=['get', 'post', 'both'], default='both', help="HTTP method to test (default: both).")
    parser.add_argument("--data", type=str, help="POST data (e.g., 'key1=value1&key2=value2').")
    parser.add_argument("--post-file", type=str, help="TXT file with POST request (SQLmap format).")
    parser.add_argument("--payload-field", type=str, help="Specific field to inject payloads.")
    parser.add_argument("--verify-execution", action="store_true", help="Verify executable XSS with headless browser.")
    parser.add_argument("--new-session", action="store_true", help="Start a new session, clearing cookies.")
    parser.add_argument("--use-403-bypass", action="store_true", help="Enable 403 bypass with specialized payloads.")
    parser.add_argument("--simulate-403", action="store_true", help="Simulate a 403 response to test bypass payloads.")
    parser.add_argument("--no-live-status", action="store_true", help="Disable live status updates.")
    parser.add_argument("--anonymous", action="store_true", help="Run in anonymous mode (no identifiable data).")
    parser.add_argument("--use-tor", action="store_true", help="Route traffic through Tor (requires Tor service running).")

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
    if args.anonymous:
        print(f"{GREEN}[+] Anonymous mode enabled: No identifiable data will be exposed{RESET}")
    if args.use_tor:
        print(f"{GREEN}[+] Tor routing enabled (ensure Tor service is running on port 9050){RESET}")
    
    return args

def setup_tor_proxy():
    socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
    sock.socket = socks.socksocket
    logging.info("Tor proxy configured (SOCKS5 localhost:9050)")

class PayloadGenerator:
    def __init__(self, payloads_dir: str, payload_file: Optional[str] = None, bypass_needed: bool = False, use_403_bypass: bool = False, stealth: bool = False):
        self.payloads_dir = payloads_dir
        self.payload_file = payload_file
        self.bypass_needed = bypass_needed
        self.use_403_bypass = use_403_bypass
        self.stealth = stealth
        self.payloads = self.load_payloads()
        self.previous_success = []

    def load_payloads(self) -> List[str]:
        default_payloads = [
            "<script>alert('test')</script>",
            "<img src=x onerror=alert('test')>",
            "<svg onload=alert('test')>",
            "javascript:alert('test')"
        ]
        stealth_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>"
        ]
        
        payloads = []
        if self.payload_file:
            file_path = sanitize_path(self.payload_file)
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_payloads = [sanitize_input(line.strip()) for line in f if line.strip()]
                        payloads.extend(file_payloads)
                        logging.info(f"Loaded {len(file_payloads)} payloads from file")
                else:
                    logging.warning(f"Payload file not found; using defaults")
                    payloads = stealth_payloads if self.stealth else default_payloads
            except Exception as e:
                logging.error(f"Error loading payloads: {e}")
                payloads = stealth_payloads if self.stealth else default_payloads
        else:
            if not os.path.exists(self.payloads_dir):
                logging.error(f"Payloads directory not found!")
                return stealth_payloads if self.stealth else default_payloads

            category_map = {
                'waf_bypass': 'waf_bypass.txt',
                '403bypass': '403bypass.txt',
                'default': ['advanced_xss.txt', 'xss_payloads.txt', 'basic_xss.txt', 'custom_payloads.txt']
            }

            selected_category = 'waf_bypass' if self.bypass_needed else '403bypass' if self.use_403_bypass else 'default'
            all_files = [f for f in os.listdir(self.payloads_dir) if f.endswith('.txt')]
            if not all_files:
                logging.warning(f"No payload files found; using defaults")
                return stealth_payloads if self.stealth else default_payloads

            if selected_category == 'default':
                for filename in category_map['default']:
                    file_path = os.path.join(self.payloads_dir, filename)
                    try:
                        if os.path.exists(file_path):
                            with open(file_path, 'r', encoding='utf-8') as f:
                                file_payloads = [sanitize_input(line.strip()) for line in f if line.strip()]
                                payloads.extend(file_payloads)
                                logging.info(f"Loaded {len(file_payloads)} payloads from file")
                        else:
                            logging.warning(f"Payload file not found")
                    except Exception as e:
                        logging.error(f"Error loading payloads: {e}")
            else:
                file_path = os.path.join(self.payloads_dir, category_map[selected_category])
                try:
                    if os.path.exists(file_path):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                        logging.info(f"Loaded {selected_category} payloads")
                    else:
                        logging.warning(f"{selected_category} file not found; using defaults")
                        payloads = default_payloads
                except Exception as e:
                    logging.error(f"Error loading payloads: {e}")
                    payloads = default_payloads

        unique_payloads = list(set(payloads))
        unique_payloads = [p for p in unique_payloads if p.strip()]
        logging.debug(f"Total unique payloads loaded: {len(unique_payloads)}")
        return unique_payloads if unique_payloads else (stealth_payloads if self.stealth else default_payloads)

    def generate(self) -> List[str]:
        return self.payloads

    def update_success(self, payload: str):
        self.previous_success.append(payload)

class Venom:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.session = requests.Session()
        self.session.mount('http://', HTTPAdapter(max_retries=Retry(total=10, backoff_factor=2), pool_maxsize=10))
        self.session.mount('https://', HTTPAdapter(max_retries=Retry(total=10, backoff_factor=2), pool_maxsize=10))
        self.session.headers.update({
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })

        if args.use_tor:
            setup_tor_proxy()
        if args.anonymous:
            self.session.headers.pop('Referer', None)  # Remove identifiable headers
            logging.getLogger().handlers = [logging.FileHandler(log_file, mode='a', encoding='utf-8')]  # Disable console logging

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
        self.bypass_performed = False
        self.use_403_bypass = args.use_403_bypass
        self.is_waf_detected = False
        self.active_params = []
        self.headless_driver = None
        self.headless_runs = 0

        self.initial_waf_ips_check()
        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.args.payload_file, self.bypass_performed, self.use_403_bypass, self.args.stealth)
        self.payloads = self.payload_generator.generate()
        self.total_payloads = len(self.payloads)
        if args.verify_execution and not args.anonymous:  # Disable browser in anonymous mode to avoid traces
            self._init_headless_browser()

    def _init_headless_browser(self):
        for attempt in range(5):
            try:
                options = Options()
                options.headless = True
                options.add_argument(f"--user-data-dir={tempfile.mkdtemp(prefix='anon_')}")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--disable-web-security")
                options.add_argument("--disable-gpu")
                port = random.randint(40000, 50000)
                while True:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.bind(('localhost', port))
                        break
                    except OSError:
                        port += 1
                options.add_argument(f"--remote-debugging-port={port}")
                self.headless_driver = webdriver.Chrome(options=options)
                self.headless_driver.set_page_load_timeout(120)
                logging.info(f"Headless browser initialized")
                return
            except WebDriverException as e:
                logging.error(f"Headless browser init failed (attempt {attempt+1})")
                time.sleep(2)
        logging.error("Headless browser init failed after retries")
        self.args.verify_execution = False

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

    def initial_waf_ips_check(self):
        try:
            test_payloads = ["<script>alert('test')</script>", "1' OR '1'='1"]
            for payload in test_payloads:
                response = self.session.get(self.args.url + "?test=" + urlencode({'': payload})[1:], timeout=self.args.timeout, verify=True)
                if response.status_code in [403, 429] or 'blocked' in response.text.lower():
                    self.waf_ips_status = "WAF detected"
                    self.is_waf_detected = True
                    break
            if not self.is_waf_detected:
                self.waf_ips_status = "No WAF/IPS detected"
            logging.info(f"WAF/IPS check result: {self.waf_ips_status}")
        except RequestException:
            self.waf_ips_status = "Check failed"
            logging.error("WAF/IPS check failed")

    def check_connection(self, url: str) -> bool:
        try:
            response = self.session.head(url, timeout=self.args.timeout, allow_redirects=True)
            return response.status_code < 400
        except RequestException:
            logging.error("Connection check failed")
            return False

    def crawl_links(self, base_url: str) -> List[str]:
        urls = set([base_url])
        if not self.check_connection(base_url):
            logging.error("Base URL not reachable")
            return list(urls)
        
        try:
            response = self.session.get(base_url, timeout=self.args.timeout, verify=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(base_url, link['href'])
                parsed = urlparse(absolute_url)
                if parsed.netloc == self.domain and absolute_url not in self.visited_urls:
                    urls.add(absolute_url)
                    self.task_queue.put((absolute_url, 'get', {}))
            logging.info(f"Crawled {len(urls)} URLs")
        except RequestException:
            logging.error("Crawl failed")
        return list(urls)

    def extract_params(self, url: str, response_text: str) -> List[str]:
        params = set(parse_qs(urlparse(url).query).keys())
        soup = BeautifulSoup(response_text, 'html.parser')
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                if input_tag.get('name'):
                    params.add(input_tag['name'])
        self.active_params = list(params)
        logging.debug(f"Extracted parameters: {len(self.active_params)}")
        return self.active_params

    def inject_payload(self, url: str, method: str, payload: str, param: str = None, data: Dict[str, str] = None) -> tuple[Optional[str], int]:
        try:
            if method.lower() == 'get':
                target_url = url
                if param:
                    parsed = urlparse(url)
                    query = parse_qs(parsed.query)
                    query[param] = payload
                    target_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
                response = self.session.get(target_url, timeout=self.args.timeout, verify=True)
            else:
                data = data.copy() if data else self.post_data.copy()
                if param:
                    data[param] = payload
                response = self.session.post(url, data=data, timeout=self.args.timeout, verify=True)
            return response.text, response.status_code
        except RequestException:
            logging.error("Payload injection failed")
            return None, 0

    def scan_url(self, url: str, method: str, data: Dict[str, str]):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=self.args.timeout, verify=True) if method.lower() == 'get' else \
                      self.session.post(url, data=data, timeout=self.args.timeout, verify=True)
            params = self.extract_params(url, response.text)
            if not params and method.lower() == 'post':
                params = list(data.keys())
            
            payloads = self.payload_generator.generate()
            
            def test_payload(param, payload):
                self.current_payload = payload
                self.current_param = param
                self.current_method = method.upper()
                self.current_cookie = "Hidden" if self.args.anonymous else str(self.session.cookies.get_dict())
                resp_text, status = self.inject_payload(url, method, payload, param, data)
                test_count = self.total_tests.increment()
                
                if resp_text and status == 200:
                    soup = BeautifulSoup(resp_text, 'html.parser')
                    if is_reflected(payload, resp_text):
                        logging.info(f"Vulnerability found at {url} - Param: {param}")
                
                time.sleep(random.uniform(self.args.min_delay, self.args.max_delay))

            with ThreadPoolExecutor(max_workers=min(10, self.args.workers)) as executor:
                for param in params:
                    executor.map(lambda p: test_payload(param, p), payloads)
        
        except RequestException:
            logging.error("Scan failed")

    def worker(self):
        while self.running:
            try:
                url, method, data = self.task_queue.get(timeout=1)
                self.scan_url(url, method, data)
                self.task_queue.task_done()
            except queue.Empty:
                break
            except Exception:
                logging.error("Worker error")

    def display_status(self):
        while self.running:
            current_time = time.time()
            if current_time - self.last_display_time >= 1 and not self.args.no_live_status:
                elapsed = current_time - self.start_time
                tests_per_sec = self.total_tests.get() / elapsed if elapsed > 0 else 0
                status = f"""
{BLUE}╔════ Venom Live Status @ {time.strftime('%H:%M:%S')} ═════════════════════════════════════╗{RESET}
{BLUE}║{RESET} Tests Run: {YELLOW}{self.total_tests.get():>5}{RESET} | Payloads: {YELLOW}{self.total_payloads}{RESET} | Vulns: {RED}{len(self.vulnerabilities)}{RESET} | Speed: {GREEN}{tests_per_sec:.2f} t/s{RESET}
{BLUE}║{RESET} Current: {CYAN}{self.current_method} {self.current_param}={self.current_payload}{RESET}
{BLUE}║{RESET} Cookies: {WHITE}{self.current_cookie}{RESET}
{BLUE}║{RESET} WAF/IPS: {ORANGE}{self.waf_ips_status}{RESET} | Workers: {PURPLE}{self.args.workers}{RESET} | Domain: {WHITE}{self.domain}{RESET}
{BLUE}╚════════════════════════════════════════════════════════════════════════════════════╝{RESET}
"""
                print(status, end='\r' if os.name == 'nt' else '')
                self.last_display_time = current_time
            time.sleep(0.1)

    def run(self):
        if not self.check_connection(self.args.url):
            print(f"{RED}[!] Target URL unreachable. Exiting.{RESET}")
            return
        
        urls = self.crawl_links(self.args.url)
        for url in urls:
            if self.args.method in ['get', 'both']:
                self.task_queue.put((url, 'get', {}))
            if self.args.method in ['post', 'both']:
                self.task_queue.put((url, 'post', self.post_data))

        status_thread = threading.Thread(target=self.display_status)
        status_thread.start()

        with ThreadPoolExecutor(max_workers=self.args.workers) as executor:
            for _ in range(self.args.workers):
                executor.submit(self.worker)

        self.task_queue.join()
        self.running = False
        status_thread.join()

        self.generate_report()

    def generate_report(self):
        print(f"\n{GREEN}╔════ Venom Scan Report @ {time.strftime('%Y-%m-%d %H:%M:%S')} ═════════════════════╗{RESET}")
        print(f"{GREEN}║{RESET} Target: {WHITE}{self.args.url}{RESET}")
        print(f"{GREEN}║{RESET} Total Tests: {YELLOW}{self.total_tests.get()}{RESET} | Payloads: {YELLOW}{self.total_payloads}{RESET} | Duration: {CYAN}{time.time() - self.start_time:.2f}s{RESET}")
        print(f"{GREEN}║{RESET} Vulnerabilities Found: {RED}{len(self.vulnerabilities)}{RESET}")
        if self.vulnerabilities:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{GREEN}║{RESET} {i}. {RED}{vuln['type']}{RESET}")
                print(f"{GREEN}║{RESET}    URL: {WHITE}{vuln['url']}{RESET}")
                print(f"{GREEN}║{RESET}    Full URL: {WHITE}{vuln['full_url']}{RESET}")
                print(f"{GREEN}║{RESET}    Method: {CYAN}{vuln['method']}{RESET}")
                print(f"{GREEN}║{RESET}    Parameter: {YELLOW}{vuln['param']}{RESET}")
                print(f"{GREEN}║{RESET}    Payload: {PURPLE}{vuln['payload']}{RESET}")
        else:
            print(f"{GREEN}║{RESET}    {GREEN}No vulnerabilities detected.{RESET}")
        print(f"{GREEN}╚════════════════════════════════════════════════════════════════════╝{RESET}")

def is_reflected(payload: str, response_text: str) -> bool:
    if not payload.strip():
        return False
    patterns = [payload, payload.lower(), html.escape(payload)]
    for pattern in patterns:
        if pattern in response_text:
            return True
    return False

if __name__ == "__main__":
    args = parse_args()
    venom = Venom(args)
    venom.run()
