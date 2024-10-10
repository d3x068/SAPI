import requests
from colorama import Fore, Style, init
import sys
import json
import subprocess

# Function to test if an endpoint exists
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
    
# Function to fuzz the endpoints
def fuzz_endpoints(base_url, wordlist_file):
    with open(wordlist_file, 'r') as f:
        endpoints = [line.strip() for line in f.readlines()]
    
    valid_endpoints = []
    
    for endpoint in endpoints:
        if check_endpoint(base_url, endpoint):
            valid_endpoints.append(endpoint)
    
    return valid_endpoints

def call_sqlmap(base_url,endpoint):
    url = f"{base_url}/{endpoint}"

    try:
        print("running sqlmap")
        result = subprocess.run(
            [
                'python','C:/Users/user/d3x068/tools/sqlmap/sqlmap.py','-u',url,'--method=POST','--data={"username":"admin","password":"admin123"}','--batch'
            ],
            capture_output=True,
            text=True
        )

        if "is vulnerable" in result.stdout :
            print(f"{Fore.YELLOW}[!] SQL Injection vulnerability detected by SQLMap at {url}")
    except Exception as e:
        print(f"error running : {e}")


# Main function to run fuzzing and vulnerability scanning
def scan_vulnerabilities(base_url, wordlist_file):
    
    valid_endpoints = fuzz_endpoints(base_url, wordlist_file)

    for endpoint in valid_endpoints:
        print(f"\n{Fore.CYAN}[*] Testing vulnerabilities for /{endpoint}")
        call_sqlmap(base_url,endpoint)
        

if __name__ == "__main__":

    try:
        base_url = sys.argv[sys.argv.index('--url') + 1]
        wordlist_file = sys.argv[sys.argv.index('--endpoints') + 1]
    except (ValueError, IndexError):
        print(f"{Fore.RED}Error: Missing required arguments. Use '--help' for usage instructions.")
        sys.exit(1)

    scan_vulnerabilities(base_url, wordlist_file)
