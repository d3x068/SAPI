import requests
from colorama import Fore, Style, init
import sys

# Initialize colorama
init(autoreset=True)

# Banner for the app
def print_banner():
    print(f"{Fore.GREEN}")
    print(r"""                                          
     █                                                     █     
      ██                                                 ██      
       ██ ████ █████    █████       █████    █████ ████ ██       
          ██ █████ ███████████████████████████ █████ ██          
                        █████████████████                        
                         ███████████████                         
                         ███████████████                         
                         █ ███████████ █                         
                         █    ██████   █                         
                           █ █████████                           
                           ███████████                           
                           ███████████                           
                             ██ ████                             
                             ██ █  █                             
                             ██ █  █                             
                              ██████                             
                                                                                                                                                 
    """)
    print(f"{Fore.YELLOW}SAPI - Scan API {Fore.BLUE}(v1.0)")
    print(f"{Fore.GREEN}Author : d3x068\n")
    
# Help feature
def print_help():
    print(f"{Fore.CYAN}Usage:")
    print(f"  python sapi.py [OPTIONS]")
    print(f"\n{Fore.CYAN}Options:")
    print(f"  --url <target_url>            Specify the target URL to scan")
    print(f"  --lhost <listening_host>      Specify the listening host to scan RFI")
    print(f"  --endpoints <file>            Specify the file containing the endpoints wordlist")
    print(f"  --help                        Show this help message and exit\n")
    print(f"{Fore.CYAN}Example:")
    print(f"  python sapi.py --url http://127.0.0.1:5000 --lhost http://burp_collaborator.com --endpoints endpoints.txt\n")

# if an endpoint exists?
def check_endpoint(base_url, endpoint):
    url = f"{base_url}/{endpoint}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 404:
            print(f"{Fore.GREEN}[+] Found endpoint: {url}")
            return True
        else:
            #print(f"{Fore.RED}[-] Endpoint not found or inaccessible: {url} (Status: {response.status_code})")
            return False
    except requests.RequestException as e:
        print(f"{Fore.RED}[-] Error accessing {url}: {e}")
        return False

# read payloads from a file
def read_payloads(wordlist_file):
    with open(wordlist_file, 'r') as f:
        payloads = [line.strip() for line in f.readlines()]
    return payloads

# SQL Injection vulnerabilities with multiple payloads
def test_sqli(base_url, endpoint, payloads):
    for payload in payloads:
        response = requests.post(f"{base_url}/{endpoint}", data={'input': payload})
        if "error" not in response.text:
            print(f"{Fore.YELLOW}[!] Potential SQL Injection with payload: {payload} at /{endpoint}")

# XSS vulnerabilities with multiple payloads
def test_xss(base_url, endpoint, payloads):
    for payload in payloads:
        data = {"username":payload}
        response = requests.post(f"{base_url}/{endpoint}",json=data)
        if payload in response.text:
            print(f"{Fore.RED}[!] Potential XSS with payload: {payload} at /{endpoint} in parameter username")

# LFI vulnerabilities with multiple payloads
def test_lfi(base_url, endpoint, payloads):
    for payload in payloads:
        data = {"filename":payload}
        response = requests.post(f"{base_url}/{endpoint}",json=data)
        if "root:x" in response.text or "hosts" in response.text:
            print(f"{Fore.YELLOW}[!] Potential LFI with payload: {payload} at /{endpoint} parameter filename")
        

# RFI vulnerabilities with multiple payloads
def test_rfi(base_url, endpoint, payload):
    data = {"imagelink":payload}
    response = requests.post(f"{base_url}/{endpoint}",json=data)
    fetch_resp = requests.get(url=payload, timeout=2, verify=False).text
    if response.status_code == 200 and fetch_resp in response.text:
        print(f"{Fore.YELLOW}[!] Potential RFI with payload: {payload} at /{endpoint}")

# SSTI vulnerabilities with multiple payloads
def test_ssti(base_url, endpoint, payloads):
    for payload in payloads:
        data = {"mathexp":payload}
        response = requests.post(f"{base_url}/{endpoint}",json=data)
        if "49" in response.text:  # Example check if 7*7 renders as 49
            print(f"{Fore.YELLOW}[!] Potential SSTI with payload: {payload} at /{endpoint}")
            break
        

# host header injection vulnerabilities
def test_hhi(base_url, endpoint):
    url = f"{base_url}/{endpoint}"
    # Injected host value
    # next : lets try to use burp collaborator
    injected_host = "evil.com"
    
    try:
        # Make a request with the Host header manipulated
        data = {"email":"evilmail@mail.com"}
        response = requests.post(url, headers={"Host": injected_host},json=data, timeout=5)
        
        # Check if the injected host is reflected in the response
        if injected_host in response.text or response.headers.get('Location', '').find(injected_host) != -1:
            print(f"{Fore.YELLOW}[!] Host Header Injection vulnerability detected at {url}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[-] Error testing Host Header Injection at {url}: {e}")


# fuzz the endpoints
def fuzz_endpoints(base_url, wordlist_file):
    with open(wordlist_file, 'r') as f:
        endpoints = [line.strip() for line in f.readlines()]
    
    valid_endpoints = []
    
    for endpoint in endpoints:
        if check_endpoint(base_url, endpoint):
            valid_endpoints.append(endpoint)
    
    return valid_endpoints

# Main function
def scan_vulnerabilities(base_url, wordlist_file, lhost):

    valid_endpoints = fuzz_endpoints(base_url, wordlist_file)

    sqli_payloads = read_payloads('sqli_payloads.txt')
    xss_payloads = read_payloads('xss_payloads.txt')
    lfi_payloads = read_payloads('lfi_payloads.txt')
    rfi_payloads = lhost
    ssti_payloads = read_payloads('ssti_payloads.txt')

    for endpoint in valid_endpoints:
        print(f"\n{Fore.CYAN}[*] Testing vulnerabilities for /{endpoint}")
        test_xss(base_url, endpoint, xss_payloads)
        test_hhi(base_url,endpoint)
        # test_sqli(base_url, endpoint, sqli_payloads)
        test_lfi(base_url, endpoint, lfi_payloads)
        test_rfi(base_url, endpoint, rfi_payloads)
        test_ssti(base_url, endpoint, ssti_payloads)

if __name__ == "__main__":
    
    print_banner()
    if '--help' in sys.argv:
        print_help()
        sys.exit()

    try:
        base_url = sys.argv[sys.argv.index('--url') + 1]
        wordlist_file = sys.argv[sys.argv.index('--endpoints') + 1]
        lhost = sys.argv[sys.argv.index('--lhost') + 1]
    except (ValueError, IndexError):
        print(f"{Fore.RED}Error: Missing required arguments. Use '--help' for usage instructions.")
        sys.exit(1)

    scan_vulnerabilities(base_url, wordlist_file, lhost)
