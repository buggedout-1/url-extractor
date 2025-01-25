#!/usr/bin/env python3

import requests
import re
import argparse
import signal
import sys
import os
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = "=== URL Extractor ==="
    terminal_width = os.get_terminal_size().columns
    print(Fore.CYAN + banner.center(terminal_width) + Style.RESET_ALL)

def extract_links_from_js(js_content):
    url_pattern = r'(https?://[^\s\'"<>]+)'
    return re.findall(url_pattern, js_content)

def filter_in_scope_urls(urls, scope, contain_equals=False, js_json_only=False):
    in_scope_urls = []
    for url in urls:
        parsed_url = urlparse(url)

        # Check if the URL is in scope
        if not parsed_url.netloc.endswith(scope):
            continue

        # Filter by URLs containing '=' if -p is passed
        if contain_equals and '=' not in url:
            continue

        # Filter by .js or .json file extensions if -j is passed
        if js_json_only and not (url.endswith('.js') or url.endswith('.json')):
            continue

        in_scope_urls.append(url)
    return in_scope_urls

def signal_handler(sig, frame):
    choice = input(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Do you want to close URL Extractor? (Y/N): ").strip().lower()
    if choice == 'y':
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Closing URL Extractor...")
        sys.exit(0)
    else:
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Continuing execution...")

def main(input_file, output_file, single_url, silent, contain_equals, js_json_only):
    clear_screen()
    print_banner()

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    js_links = []
    if single_url:
        js_links.append(single_url)
    else:
        with open(input_file, 'r') as file:
            js_links = file.readlines()

    processed_count = 0

    # Open the output file in append mode
    with open(output_file, 'a') as out_file:
        for js_link in js_links:
            js_link = js_link.strip()
            if not js_link:
                continue

            try:
                # Set a timeout of 10 seconds for the request
                response = requests.get(js_link, verify=False, timeout=10)
                response.raise_for_status()

                links = extract_links_from_js(response.text)

                # Automatically determine the scope (domain) from the input URL
                parsed_url = urlparse(js_link)
                scope = parsed_url.netloc

                # Filter links by the determined scope and apply additional filters
                scoped_links = filter_in_scope_urls(links, scope, contain_equals, js_json_only)

                # Live counter display
                processed_count += 1
                if not silent:
                    # Print the count of processed URLs on the same line
                    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {Fore.YELLOW}Extracted {len(scoped_links)} in-scope links from {js_link}{Style.RESET_ALL}")

                if not silent and scoped_links:
                    for link in scoped_links:
                        print(f"{Fore.GREEN}[+] {link}{Style.RESET_ALL}")

                if not silent and not scoped_links:
                    print(f"{Fore.RED}[INFO]{Style.RESET_ALL} {Fore.YELLOW}No in-scope URLs found in {js_link}{Style.RESET_ALL}")

                # Write each extracted in-scope link immediately to the output file
                for link in scoped_links:
                    out_file.write(link + '\n')

            except requests.exceptions.Timeout:
                if not silent:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Timeout while fetching {js_link}: Skipping this URL.")
            except requests.exceptions.SSLError as ssl_err:
                if not silent:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} SSL error while fetching {js_link}: {str(ssl_err)}")
            except requests.RequestException as e:
                if not silent:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to fetch {js_link}: {str(e)}")

    if not silent:
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Processed {processed_count} URLs in total.")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Extract URLs from JavaScript files.')
    parser.add_argument('-l', '--input_file', help='File with list of JS URLs')
    parser.add_argument('-o', '--output_file', default='extracted_links.txt', help='File to save extracted links')
    parser.add_argument('--url', help='Single JavaScript file URL to process')
    parser.add_argument('--silent', action='store_true', help='Suppress detailed output, only show processed count')
    parser.add_argument('-p', '--contains_equals', action='store_true', help='Only extract URLs that contain "="')
    parser.add_argument('-j', '--js_json_only', action='store_true', help='Only extract URLs that end with .js or .json')
    args = parser.parse_args()

    if args.url and args.input_file:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Please provide either an input file or a single URL, not both.")
        sys.exit(1)

    main(args.input_file, args.output_file, args.url, args.silent, args.contains_equals, args.js_json_only)
