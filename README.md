![יניב](https://github.com/user-attachments/assets/bb26572f-2d8b-400e-b4e6-7d70536cc51e)
Venom Advanced XSS Scanner (Version 5.45)
Overview

Venom Advanced XSS Scanner is a cutting-edge, open-source tool designed for ethical penetration testers and security researchers to identify Cross-Site Scripting (XSS) vulnerabilities in web applications. Built with Python, Venom combines precision, performance, and flexibility to deliver a professional-grade solution for vulnerability assessment. Version 5.48 introduces significant enhancements, making it a robust choice for both novice and expert users in the cybersecurity community.

Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities with high accuracy. This version supports HTTP/HTTPS, smart POST/GET requests, custom POST from TXT files, session management, and AI model selection.

Key Features

● Advanced XSS detection with extended event handlers
● Parallel payload testing with adaptive throttling
● Custom payload integration from /usr/local/bin/payloads/
● AI-driven payload optimization with WAF/403 bypass
● Subdomain scanning from text file support
● Comprehensive parameter testing for XSS
● Enhanced endpoint discovery and crawling
● Anonymous operation mode with Tor support


Why Venom?

Venom stands out for its balance of precision, speed, and usability. Whether you’re a penetration tester validating a client’s application, a developer securing your own code, or a researcher exploring XSS techniques, Venom provides the tools you need to succeed—all while upholding ethical standards.

Get Started
Clone the repository, install dependencies, and run your first scan. Join me in advancing web security—one vulnerability at a time!

Venom Advanced XSS Scanner is a professional-grade tool for ethical penetration testers to identify XSS vulnerabilities with high accuracy. This version supports HTTP/HTTPS, smart POST/GET requests, custom POST from TXT files, multiple custom headers, 403 bypass, and two AI-assisted payload optimization modes:
- Local AI: Learns from past scans to optimize payloads (no API key needed).
- External AI: Uses an external AI platform (requires --ai-key and --ai-platform).

Venom Advanced XSS Scanner is a tool for ethical penetration testers to detect XSS vulnerabilities anonymously. Version 5.48 supports over 8000 payloads, extended event handlers, AI-driven WAF/403 bypass, subdomain scanning, and comprehensive parameter testing.

Usage:
  python3 venom.py <url> --scan-xss [options]

Examples:
  python3 venom.py http://target.com --scan-xss --anonymous --use-tor -w 5 --ai-assist --subdomains subdomains.txt
    - Anonymous scan with Tor, AI optimization, and subdomain list.
  python3 venom.py http://example.com --scan-xss --stealth --use-403-bypass --log-output --all-params
    - Stealth mode with 403 bypass, live logging, and all parameter testing.
  python3 venom.py http://test.com --scan-xss --extended-events --extra-params "email,id,search" --ai-platform xai-grok --ai-key YOUR_API_KEY
    - Advanced scan with extended events, extra parameters, and AI assistance via xAI Grok.

positional arguments:
  url                   Target URL to scan (e.g., http://target.com).

options:
  -h, --help            show this help message and exit
  -w, --workers WORKERS
                        Number of concurrent threads (default: 5, max: 20).
  --scan-xss            Enable XSS scanning (required).
  --subdomains SUBDOMAINS
                        Text file containing subdomains to scan (e.g., subdomains.txt).
  --all-params          Ensure all discovered parameters are tested for XSS.
  --payloads-dir PAYLOADS_DIR
                        Directory with custom payload files (default: /usr/local/bin/payloads/).
  --payload-file PAYLOAD_FILE
                        Specific payload file to use instead of directory.
  --timeout TIMEOUT     HTTP request timeout in seconds (default: 30).
  --verbose             Enable detailed logging.
  --stealth             Enable stealth mode: 2 workers, 5-15s delays.
  --min-delay MIN_DELAY
                        Min delay between requests (default: 0.1 or 5 in stealth).
  --max-delay MAX_DELAY
                        Max delay between requests (default: 0.5 or 15 in stealth).
  --full-report         Show detailed vulnerabilities in report.
  --export-report EXPORT_REPORT
                        Export report to a file (e.g., report.json, report.csv).
  -H, --headers HEADERS
                        Custom headers (e.g., 'Cookie: session=abc123').
  --method {get,post,both}
                        HTTP method to test (default: both).
  --data DATA           POST data (e.g., 'key1=value1&key2=value2').
  --post-file POST_FILE
                        TXT file with POST request.
  --new-session         Start a new session, clearing cookies.
  --use-403-bypass      Prioritize 403 bypass payloads from 403bypass.txt.
  --simulate-403        Simulate a 403 response to test bypass payloads.
  --no-live-status      Disable live status updates.
  --anonymous           Run in anonymous mode (no identifiable data).
  --use-tor             Route traffic through Tor (requires Tor on port 9050).
  --ai-assist           Enable AI-driven payload optimization and WAF/403 bypass.
  --ai-key AI_KEY       API key for external AI platform (required if --ai-platform is used).
  --ai-platform {xai-grok,openai-gpt3,google-gemini}
                        External AI platform for optimization (requires --ai-key).
  --log-output          Enable console logging alongside file (overrides anonymous mode restriction).
  --extended-events     Use extended event handlers (onmouseover, onclick, etc.).
  --extra-params EXTRA_PARAMS
                        Comma-separated list of additional parameters to test (e.g., 'email,id,search'). 
  
  
  
  
  
  
  
  
  
  
  ![venom3](https://github.com/user-attachments/assets/6eb037b4-362c-4faf-a103-98284706e4b3)
                                           



