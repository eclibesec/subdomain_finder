import os
import sys
import subprocess
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from colorama import init, Fore, Style
import time

init(autoreset=True)

# Constants
API_URL = "https://eclipsesec.tech/api/"
FILTERED_SUBDOMAINS = [
    'www.', 'webmail.', 'cpanel.', 'cpcalendars.', 'cpcontacts.', 
    'webdisk.', 'mail.', 'whm.', 'autodiscover.'
]
MAX_THREADS = 500
RETRY_STATUS_CODES = {502, 500, 520}
DEBUG_FILE = "debug.txt"

def install_required_packages():
    packages = ["requests", "colorama"]
    for package in packages:
        try:
            __import__(package)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

install_required_packages()

def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def validate_api_key(apikey: str):
    url = f"https://eclipsesec.tech/api/?apikey={apikey}&validate=true"
    try:
        response = requests.get(url)
        response.raise_for_status()
        body = response.json()
        with open(DEBUG_FILE, "a", encoding="utf-8") as debug_file:
            debug_file.write(f"API Response: {body}\n")
        
        if body.get('status') == "valid":
            save_api_key(apikey)
            return body.get('user'), True
        else:
            with open(DEBUG_FILE, "a", encoding="utf-8") as debug_file:
                debug_file.write(f"Invalid API key: {body.get('message', 'Unknown error')}\n")
            print(Fore.RED + f"Invalid API key: {body.get('message', 'Unknown error')}" + Style.RESET_ALL)
            return "", False
    except Exception as e:
        with open(DEBUG_FILE, "a", encoding="utf-8") as debug_file:
            debug_file.write(f"Error during API key validation: {str(e)}\n")
        print(Fore.RED + f"API key validation failed: {e}" + Style.RESET_ALL)
        return "", False

def save_api_key(apikey: str):
    with open("apikey.txt", "w") as file:
        file.write(apikey)
        
def get_subdomains(domain: str, apikey: str) -> List[str]:
    while True:
        try:
            response = requests.get(API_URL, params={"subdomain": domain, "apikey": apikey})
            response.raise_for_status()
            if response.status_code in RETRY_STATUS_CODES:
                time.sleep(2)
                continue
            data = response.json()
            return data.get("subdomains", [])
        except requests.RequestException as e:
            if response and response.status_code not in RETRY_STATUS_CODES:
                print(Fore.RED + f"Error fetching subdomains for {domain}: {e}")
            continue

def filter_subdomains(subdomains: List[str]) -> List[str]:
    return [subdomain for subdomain in subdomains if not any(subdomain.startswith(f) for f in FILTERED_SUBDOMAINS)]

def process_file(input_file: str, auto_filter: bool, output_file: str, thread_count: int, apikey: str):
    clear_screen()
    
    with open(input_file, 'r') as file:
        domains = [line.strip() for line in file if line.strip()]
    print(Fore.CYAN + "Scanning domains from {}...".format(input_file))
    
    thread_count = min(thread_count, MAX_THREADS)
    
    with open(output_file, 'w') as file:
        def write_subdomains(domain: str):
            subdomains = get_subdomains(domain, apikey)
            if subdomains:
                if auto_filter:
                    subdomains = filter_subdomains(subdomains)
                for subdomain in set(subdomains):
                    file.write(f"{subdomain}\n")
                print(Fore.GREEN + f"{domain} >>> {len(subdomains)} subdomain(s) found")
                
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(write_subdomains, domain) for domain in domains]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(Fore.RED + f"Error processing domain: {e}")
                    
    print(Fore.YELLOW + "Subdomains saved to " + Fore.CYAN + f"{output_file}")

if __name__ == "__main__":
    clear_screen()
    print("""█▀ █░█ █▄▄ █▀▄ █▀█ █▀▄▀█ ▄▀█ █ █▄░█   █▀▀ █ █▄░█ █▀▄ █▀▀ █▀█
▄█ █▄█ █▄█ █▄▀ █▄█ █░▀░█ █▀█ █ █░▀█   █▀░ █ █░▀█ █▄▀ ██▄ █▀▄        
- Subdomain finder - eclipse security labs
- visit : https://eclipsesec.tech/""")
    
    apikey = input(Fore.CYAN + "$ Enter your API key: ").strip()
    
    user, valid = validate_api_key(apikey)
    if not valid:
        print(Fore.RED + "Please register for an API key at: https://eclipsesec.tech/register")
        sys.exit(1)
    
    input_file = input(Fore.CYAN + "$ Enter Your File: ").strip()
    auto_filter = input(Fore.CYAN + "$ Auto filter subdomain [ y/n ]: ").strip().lower() == 'y'
    output_file = input(Fore.CYAN + "$ Save to: ").strip()
    thread_count = int(input(Fore.CYAN + "Thread: ").strip())
    
    process_file(input_file, auto_filter, output_file, thread_count, apikey)
