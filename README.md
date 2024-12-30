# SAPI - Scan API Vulnerability Scanner

SAPI is a Python-based API vulnerability scanner designed to detect various security flaws, including XSS, SQL Injection (via SQLMap), Local/Remote File Inclusion, Server-Side Template Injection, and Host Header Injection. The app can fuzz API endpoints from a wordlist and perform POST requests with a JSON body to test vulnerabilities. Used for fulfill the technical test.

**Disclaimer**: This project created by d3x068 (Wildan Zaim Syaddad)

## Setup Instructions

```bash
git clone https://github.com/d3x068/SAPI.git
cd SAPI
```

### Install the required Python packages:

```bash
pip install -r req.txt
```

### Run the application:

```bash   
python sapi.py
```

## Features
1. Fuzz API endpoints from a wordlist
2. Detect security vulnerabilities, including:
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Server-Side Template Injection (SSTI)
- Host Header Injection (HHI)

## Usage
```bash
python sapi.py --help
```

## Disclaimer

This project is for scanning https://github.com/michealkeines/Vulnerable-API