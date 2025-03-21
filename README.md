![יניב](https://github.com/user-attachments/assets/bb26572f-2d8b-400e-b4e6-7d70536cc51e)


About the Tool: Venom Advanced XSS Scanner 2025

Overview
What is Venom Advanced XSS Scanner?
Venom is a command-line tool created by Yaniv Avisror, labeled as Version 5.20, with a futuristic branding of "2025." It’s designed to automate the process of finding XSS vulnerabilities—security flaws where malicious scripts can be injected into web pages viewed by other users. XSS is a critical web security issue, often exploited to steal data, hijack sessions, or deface websites.

The tool stands out by offering advanced features like session management, support for both GET and POST requests, AI-driven payload optimization, and colorful, user-friendly output. It’s intended for ethical use only, as emphasized by the mandatory "YES/NO" prompt at startup.
Key Features
Here’s a rundown of Venom’s main features, extracted from the script and its banner:

Accurate XSS Detection with Context-Aware Analysis:
Venom doesn’t just throw payloads at a site; it analyzes responses to determine if a payload is reflected (appears in the output) and executable (can run in a script context). It uses similarity checks (via TF-IDF and cosine similarity) to avoid false positives.
Smart Session-Aware POST/GET Scanning:
It supports both GET (query string) and POST (form data) requests, making it versatile for different web inputs.
It can maintain or establish user sessions using login credentials, cookies, or auto-login attempts, ensuring it can scan authenticated areas of a site.
Custom POST Requests from TXT Files:
You can specify a POST request in a text file (e.g., with headers and data), allowing precise testing of specific endpoints.
Dynamic Response Analysis:
Compares responses to a baseline to detect changes caused by payloads, enhancing detection accuracy.
Checks for executable contexts (e.g., <script>, onerror) and escaping (e.g., breaking out of quotes).
WAF/CSP Detection with Adaptive Strategies:
Detects Web Application Firewalls (WAFs) and Content Security Policies (CSP) by inspecting headers.
Adapts by switching to bypass payloads (e.g., 403bypass.txt) or enabling stealth mode when protections are detected.
Payloads from Local Files and GitHub:
Loads XSS payloads from local files (e.g., advanced_xss.txt) and fetches additional ones from GitHub repositories like PayloadBox and PayloadsAllTheThings.
AI-Driven Payload Optimization:
Optionally uses an AI model (default: xai-grok) to suggest optimized payloads based on response content, improving effectiveness against specific targets.
Colorful and Detailed Output:
Uses ANSI color codes for a visually appealing interface, making it easy to track progress, view vulnerabilities, and read reports.

● Accurate XSS detection with context-aware analysis
● Smart session-aware POST/GET scanning with login support
● Support for custom POST requests from TXT files
● Dynamic response analysis with similarity checking
● WAF/CSP detection with adaptive strategies
● Payloads sourced from local files and GitHub
● AI-driven payload optimization with model selection

Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities with high accuracy. This version supports HTTP/HTTPS, smart POST/GET requests, custom POST from TXT files, session management, and AI model selection.

Technical Components
Libraries:
requests: For HTTP requests and session management.
BeautifulSoup: Parses HTML to find forms and injection points.
sklearn: For TF-IDF vectorization and similarity analysis.
threading/concurrent.futures: Multi-threaded scanning for speed.
Classes:
ThreadSafeCounter: Thread-safe counter for tracking tests.
PayloadGenerator: Manages XSS payload loading and optimization.
AIAssistant: Handles AI-driven payload suggestions.
Venom: Core class orchestrating the scan.
Key Methods:
smart_session_management: Ensures valid sessions.
test_injection_points/test_form: Inject payloads into GET/POST inputs.
report_vulnerability: Formats and logs detected XSS issues.
Usage:
  python3 venom.py <url> [options]

positional arguments:
  url                   Target URL to scan

options:
  -h, --help            show this help message and exit
  -w, --workers WORKERS
                        Number of concurrent threads
  --ai-assist           Enable AI-driven payload optimization
  --ai-key AI_KEY       API key for AI assistance
  --ai-model AI_MODEL   AI model to use
  --scan-xss            Enable XSS scanning (required)
  --payloads-dir PAYLOADS_DIR
                        Directory with custom payload files
  --timeout TIMEOUT     HTTP request timeout in seconds
  --verbose             Enable detailed logging
  --stealth             Force stealth mode
  --min-delay MIN_DELAY
                        Min delay between tests in seconds
  --max-delay MAX_DELAY
                        Max delay between tests in seconds
  --full-report         Show all vulnerabilities in report
  -H H                  Custom HTTP headers (e.g., 'Cookie: session=abc')
  --method {get,post,both}
                        HTTP method to use
  --data DATA           Data for POST request (e.g., 'key1=value1&key2=value2')
  --post-file POST_FILE
                        Path to TXT file containing a POST request
  --payload-field PAYLOAD_FIELD
                        Field to inject payload into
  --login-url LOGIN_URL
                        URL for login to establish session
  --login-data LOGIN_DATA
                        Login credentials for POST (e.g., 'username=admin&password=admin')
  --auto-login          Automatically detect and attempt login
                                                                

![venom2](https://github.com/user-attachments/assets/df8600d3-893d-4bfa-9737-093b6b969bb2)


