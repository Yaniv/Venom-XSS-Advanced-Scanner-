![יניב](https://github.com/user-attachments/assets/bb26572f-2d8b-400e-b4e6-7d70536cc51e)
Venom Advanced XSS Scanner (Version 5.45)
Overview

Venom Advanced XSS Scanner is a cutting-edge, open-source tool designed for ethical penetration testers and security researchers to identify Cross-Site Scripting (XSS) vulnerabilities in web applications. Built with Python, Venom combines precision, performance, and flexibility to deliver a professional-grade solution for vulnerability assessment. Version 5.45 introduces significant enhancements, making it a robust choice for both novice and expert users in the cybersecurity community.

Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities with high accuracy. This version supports HTTP/HTTPS, smart POST/GET requests, custom POST from TXT files, session management, and AI model selection.

Key Features

Advanced XSS Detection: Utilizes precise context analysis to detect reflected and stored XSS vulnerabilities, with sanitization checks to minimize false positives.
Parallel Payload Testing: Leverages multi-threading for high-performance scanning, with adaptive throttling to respect server limits and optimize speed.
Robust Execution Verification: Integrates a headless Chrome browser to test payload execution across multiple contexts (e.g., DOM, scripts, attributes), ensuring accurate exploit confirmation.
WAF/IPS Evasion: Supports dynamic bypass payloads for Web Application Firewalls (WAF) and Intrusion Prevention Systems (IPS), with options to simulate 403 responses for testing.
Custom Payload Integration: Loads payloads from a configurable directory or a specific file, offering flexibility for tailored testing scenarios.
AI-Driven Optimization: Employs local machine learning (TF-IDF and cosine similarity) or external AI platforms (e.g., xAI, OpenAI) to prioritize effective payloads based on response context.
Detailed Reporting: Provides comprehensive reports with full URLs, complete payloads, and execution status, exportable in JSON or CSV formats for easy sharing and analysis.
Ethical Use Enforcement: Requires explicit user confirmation to ensure responsible and ethical application, aligning with professional standards.


Why Venom?

Venom stands out for its balance of precision, speed, and usability. Whether you’re a penetration tester validating a client’s application, a developer securing your own code, or a researcher exploring XSS techniques, Venom provides the tools you need to succeed—all while upholding ethical standards.

Get Started
Clone the repository, install dependencies, and run your first scan. Join me in advancing web security—one vulnerability at a time!

Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities with high accuracy. This version supports HTTP/HTTPS, smart POST/GET requests, custom POST from TXT files, multiple custom headers, 403 bypass, and two AI-assisted payload optimization modes:
- Local AI: Learns from past scans to optimize payloads (no API key needed).
- External AI: Uses an external AI platform (requires --ai-key and --ai-platform).

Usage:
  python3 venom.py <url> [options]
Examples:
  python3 venom.py http://example.com --scan-xss --ai-assist --force-headless  # Local AI with headless browser
  python3 venom.py https://example.com --scan-xss --use-403-bypass -H "Cookie: session=abc123" -H "User-Agent: VenomScanner" -w 10 --verbose  # 403 bypass with custom headers
  python3 venom.py http://example.com --scan-xss --ai-assist --ai-key "your-key" --ai-platform "xai-grok" --new-session  # External AI with new session

positional arguments:
  url                   Target URL to scan (e.g., http://example.com).

options:
  -h, --help            show this help message and exit
  -w, --workers WORKERS
                        Number of concurrent threads (default: 5, max: 20).
  --ai-assist           Enable AI-driven payload optimization. Uses local learning by default; requires --ai-key and --ai-platform for external AI.
  --ai-key AI_KEY       API key for external AI platform (e.g., 'your-xai-key'). Required with --ai-platform.
  --ai-platform {xai-grok,openai-gpt3,google-gemini}
                        External AI platform (e.g., 'xai-grok'). Requires --ai-key; optional with --ai-assist.
  --scan-xss            Enable XSS scanning (required).
  --payloads-dir PAYLOADS_DIR
                        Directory with custom payload files (default: './payloads/').
  --timeout TIMEOUT     HTTP request timeout in seconds (default: 10).
  --verbose             Enable detailed logging.
  --stealth             Enable stealth mode: 2 workers, 5-15s delays.
  --min-delay MIN_DELAY
                        Min delay between tests (default: 0.1 normal, 5 stealth).
  --max-delay MAX_DELAY
                        Max delay between tests (default: 0.5 normal, 15 stealth).
  --full-report         Show all vulnerabilities in report.
  -H, --headers HEADERS
                        Custom HTTP headers (e.g., 'Cookie: session=abc123'). Can be specified multiple times.
  --method {get,post,both}
                        HTTP method: 'get', 'post', 'both' (default).
  --data DATA           POST data (e.g., 'key1=value1&key2=value2').
  --post-file POST_FILE
                        TXT file with POST request (e.g., 'post.txt').
  --payload-field PAYLOAD_FIELD
                        Specific field to inject payloads (e.g., 'email').
  --login-url LOGIN_URL
                        Login URL for session.
  --login-data LOGIN_DATA
                        Login credentials (e.g., 'username=admin&password=pass123').
  --verify-execution    Verify high-severity payloads with headless browser.
  --force-headless      Force headless browser usage even if verification fails.
  --new-session         Force a new session by clearing cookies before scanning.
  --use-403-bypass      Enable 403 bypass using specialized payloads from payloads/403bypass.txt  
  
  
  
  
  
  
  
  
  
  
  ![venom3](https://github.com/user-attachments/assets/6eb037b4-362c-4faf-a103-98284706e4b3)
                                           



