import requests
from colorama import Fore, Style, init
import sys

# Initialize colorama
init(autoreset=True)

# Banner for the app
def print_banner():
    print(f"{Fore.GREEN}")
    print(r"""
                                                                                               @@       
                                                                                          @@@       
                                                                                         @@@@       
                                                                              @@@   @@@@@@@@        
                                                                               @@@@@@@@@@@@@@@@     
                                                                           %%  @@@@@@@@@@@@@@@@     
                                                            @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     
           @@@@@@@@@@@@@@                            %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     
         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%  %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
   @@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
   @@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    
  @@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     
  @@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                       
  @@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                        
  @@@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                           
 @@@@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                            
@@@@@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@                              
@@@@@@    @@@@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@       @@@@@@ *@@@@@@@                               
@@@@@@   @@@@@@@@@@@@@@@@                             @@@@@@  @@@@@@                                
@@@@@@  @@@@@@@@@@@@@@@ @                             @@@@@   @@@@@@                                
@@@@@   @@@@@@@@@@@@ @                                @@@@    @@@@@@                                
@@@@@   @@@@@@@@@@@@                                  @@@@    @@@@@@                                
@@@@@    @@@@@@@@@@@                                 @@@@      @@@@                                 
 %@      @@@@@@@@@@@@                               @@@@@      @@@@                                 
         @@@@@  @@@@@@                              @@@@@@     @@@@                                 
         @@@@@   @@@@@                              @@@@@@    @@@@@@                                
         @@@@@   @@@@@@@                                      @@@@@@                                
         @@@@@   @@@@@@@@                                     @@@@@@@@                              
        @@@@@@    @@@@@@@                                       @@@@                                
        @@@@@@                                                                                      
         @@@@@@                                                                                     
         @@@@@@@                                                                                                    
    """)
    print(f"{Fore.YELLOW}SAPI - Scan API {Fore.BLUE}(v1.0)")
    print(f"{Fore.MAGENTA}Logo: 🐄 (SAPI in Indonesian means cow!)\n")
    
# Help feature
def print_help():
    print(f"{Fore.CYAN}Usage:")
    print(f"  python sapi.py [OPTIONS]")
    print(f"\n{Fore.CYAN}Options:")
    print(f"  --url <target_url>      Specify the target URL to scan")
    print(f"  --endpoints <file>      Specify the file containing the endpoints wordlist")
    print(f"  --help                  Show this help message and exit\n")
    print(f"{Fore.CYAN}Example:")
    print(f"  python sapi.py --url http://127.0.0.1:5000 --endpoints endpoints.txt\n")

# Function to test if an endpoint exists
def check_endpoint(base_url, endpoint):
    url = f"{base_url}/{endpoint}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"{Fore.GREEN}[+] Found endpoint: {url}")
            return True
        else:
            print(f"{Fore.RED}[-] Endpoint not found or inaccessible: {url} (Status: {response.status_code})")
            return False
    except requests.RequestException as e:
        print(f"{Fore.RED}[-] Error accessing {url}: {e}")
        return False

# Function to read payloads from a file
def read_payloads(wordlist_file):
    with open(wordlist_file, 'r') as f:
        payloads = [line.strip() for line in f.readlines()]
    return payloads

# Vulnerability scanning functions (SQLi, XSS, LFI, RFI, SSTI) ...

# Function to fuzz the endpoints
def fuzz_endpoints(base_url, wordlist_file):
    with open(wordlist_file, 'r') as f:
        endpoints = [line.strip() for line in f.readlines()]
    
    valid_endpoints = []
    
    for endpoint in endpoints:
        if check_endpoint(base_url, endpoint):
            valid_endpoints.append(endpoint)
    
    return valid_endpoints

# Main function to run fuzzing and vulnerability scanning
def scan_vulnerabilities(base_url, wordlist_file):
    # Step 1: Fuzz the endpoints
    valid_endpoints = fuzz_endpoints(base_url, wordlist_file)

    # Step 2: Read the payloads for each vulnerability
    sqli_payloads = read_payloads('sqli_payloads.txt')
    xss_payloads = read_payloads('xss_payloads.txt')
    lfi_payloads = read_payloads('lfi_payloads.txt')
    rfi_payloads = read_payloads('rfi_payloads.txt')
    ssti_payloads = read_payloads('ssti_payloads.txt')

    # Step 3: Test vulnerabilities for each valid endpoint
    for endpoint in valid_endpoints:
        print(f"\n{Fore.CYAN}[*] Testing vulnerabilities for /{endpoint}")
        # Call vulnerability tests (SQLi, XSS, etc.) here

if __name__ == "__main__":
    # Print the banner at the start
    print_banner()
    
    # Handle command-line arguments for help and inputs
    if '--help' in sys.argv:
        print_help()
        sys.exit()

    # Get the target URL and wordlist from command-line arguments
    try:
        base_url = sys.argv[sys.argv.index('--url') + 1]
        wordlist_file = sys.argv[sys.argv.index('--endpoints') + 1]
    except (ValueError, IndexError):
        print(f"{Fore.RED}Error: Missing required arguments. Use '--help' for usage instructions.")
        sys.exit(1)

    # Start the fuzzing and scanning process
    scan_vulnerabilities(base_url, wordlist_file)
