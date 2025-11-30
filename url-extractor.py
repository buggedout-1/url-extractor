#!/usr/bin/env python3
"""
URL Extractor - Extract URLs from JavaScript files.

A Python tool for security researchers to extract and filter URLs from JavaScript files.
Supports batch processing, custom filtering, and multiple output formats.
"""

import requests
import re
import argparse
import signal
import sys
import os
import json
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Tuple, Dict, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from dataclasses import dataclass, field
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# ============================================================================
# Constants
# ============================================================================

VERSION = "2.0.0"
DEFAULT_OUTPUT_FILE = "extracted_links.txt"
DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 0
DEFAULT_THREADS = 5
DEFAULT_RETRIES = 2
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# URL regex pattern - more precise to avoid capturing invalid characters
URL_PATTERN = re.compile(
    r'https?://'                    # Protocol
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+' # Domain
    r'[a-zA-Z]{2,}'                 # TLD
    r'(?::\d{1,5})?'                # Optional port
    r'(?:/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%\-]*)?'  # Path and query
)

# Characters to strip from end of URLs
TRAILING_CHARS = r'[\s\'"<>);,\]\}\\]+'

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class Config:
    """Configuration for URL extraction."""
    input_file: Optional[str] = None
    output_file: str = DEFAULT_OUTPUT_FILE
    single_url: Optional[str] = None
    silent: bool = False
    contain_equals: bool = False
    js_json_only: bool = False
    timeout: int = DEFAULT_TIMEOUT
    delay: float = DEFAULT_DELAY
    threads: int = DEFAULT_THREADS
    retries: int = DEFAULT_RETRIES
    user_agent: str = DEFAULT_USER_AGENT
    proxy: Optional[str] = None
    include_subdomains: bool = False
    output_format: str = "txt"
    no_color: bool = False
    verbose: bool = False

@dataclass
class ExtractionResult:
    """Result of URL extraction from a single source."""
    source_url: str
    extracted_urls: List[str] = field(default_factory=list)
    error: Optional[str] = None
    status_code: Optional[int] = None

# ============================================================================
# Logging Setup
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors."""

    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def __init__(self, no_color: bool = False):
        super().__init__()
        self.no_color = no_color

    def format(self, record: logging.LogRecord) -> str:
        if self.no_color:
            prefix = f"[{record.levelname}]"
        else:
            color = self.COLORS.get(record.levelno, "")
            prefix = f"{color}[{record.levelname}]{Style.RESET_ALL}"
        return f"{prefix} {record.getMessage()}"

def setup_logging(verbose: bool = False, no_color: bool = False) -> logging.Logger:
    """Setup logging configuration."""
    logger = logging.getLogger("url_extractor")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter(no_color))
    logger.addHandler(handler)

    return logger

# ============================================================================
# Helper Functions
# ============================================================================

def get_terminal_width() -> int:
    """Get terminal width safely."""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80  # Default width

def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner(no_color: bool = False) -> None:
    """Display the application banner."""
    banner = f"=== URL Extractor v{VERSION} ==="
    terminal_width = get_terminal_width()
    if no_color:
        print(banner.center(terminal_width))
    else:
        print(Fore.CYAN + banner.center(terminal_width) + Style.RESET_ALL)

def normalize_url(url: str) -> str:
    """Normalize and clean a URL."""
    # Strip trailing invalid characters
    url = re.sub(TRAILING_CHARS + r'$', '', url)

    # Remove common JS artifacts
    url = url.rstrip('\\')

    # Handle template literals - remove if contains ${
    if '${' in url:
        url = url.split('${')[0]

    return url

def get_url_extension(url: str) -> str:
    """Get file extension from URL, ignoring query string."""
    parsed = urlparse(url)
    path = parsed.path
    if '.' in path:
        return path.rsplit('.', 1)[-1].lower()
    return ""

def get_base_domain(netloc: str) -> str:
    """Extract base domain from netloc (e.g., api.example.com -> example.com)."""
    parts = netloc.split('.')
    if len(parts) >= 2:
        # Handle common TLDs like co.uk, com.au
        if len(parts) >= 3 and parts[-2] in ('co', 'com', 'org', 'net', 'gov', 'edu'):
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return netloc

# ============================================================================
# Core Functions
# ============================================================================

def extract_links_from_js(js_content: str) -> List[str]:
    """
    Extract all URLs from JavaScript content.

    Args:
        js_content: The JavaScript file content

    Returns:
        List of extracted URLs
    """
    urls = URL_PATTERN.findall(js_content)

    # Normalize and deduplicate
    normalized = set()
    for url in urls:
        clean_url = normalize_url(url)
        if clean_url and '://' in clean_url:
            normalized.add(clean_url)

    return list(normalized)

def filter_urls(
    urls: List[str],
    scope: str,
    contain_equals: bool = False,
    js_json_only: bool = False,
    include_subdomains: bool = False
) -> List[str]:
    """
    Filter URLs based on scope and criteria.

    Args:
        urls: List of URLs to filter
        scope: Domain scope for filtering
        contain_equals: If True, only include URLs with '=' (parameters)
        js_json_only: If True, only include .js and .json files
        include_subdomains: If True, match all subdomains of base domain

    Returns:
        Filtered list of URLs
    """
    filtered = []
    base_scope = get_base_domain(scope) if include_subdomains else scope

    for url in urls:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()

        # Check scope
        if include_subdomains:
            # Match base domain and all subdomains
            if not (netloc == base_scope or netloc.endswith('.' + base_scope)):
                continue
        else:
            # Exact match on full domain
            if netloc != scope.lower():
                continue

        # Filter by URLs containing '='
        if contain_equals and '=' not in url:
            continue

        # Filter by .js or .json extensions
        if js_json_only:
            ext = get_url_extension(url)
            if ext not in ('js', 'json'):
                continue

        filtered.append(url)

    return filtered

def fetch_url(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    proxy: Optional[str] = None,
    retries: int = DEFAULT_RETRIES
) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Fetch content from a URL with retries.

    Args:
        url: The URL to fetch
        timeout: Request timeout in seconds
        user_agent: User-Agent header value
        proxy: Optional proxy URL
        retries: Number of retry attempts

    Returns:
        Tuple of (content, status_code, error_message)
    """
    headers = {
        'User-Agent': user_agent,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

    proxies = None
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy,
        }

    # Suppress SSL warnings (user requested to keep SSL bypass)
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    last_error = None
    for attempt in range(retries + 1):
        try:
            response = requests.get(
                url,
                headers=headers,
                verify=False,  # SSL bypass as requested
                timeout=timeout,
                proxies=proxies,
                allow_redirects=True
            )
            response.raise_for_status()
            return response.text, response.status_code, None

        except requests.exceptions.Timeout:
            last_error = f"Timeout after {timeout}s"
        except requests.exceptions.SSLError as e:
            last_error = f"SSL error: {str(e)[:100]}"
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection error: {str(e)[:100]}"
        except requests.exceptions.HTTPError as e:
            last_error = f"HTTP {e.response.status_code}"
            return None, e.response.status_code, last_error
        except requests.RequestException as e:
            last_error = f"Request failed: {str(e)[:100]}"

        if attempt < retries:
            time.sleep(1)  # Wait before retry

    return None, None, last_error

def process_single_url(
    js_url: str,
    config: Config,
    logger: logging.Logger
) -> ExtractionResult:
    """
    Process a single JavaScript URL.

    Args:
        js_url: URL of the JavaScript file
        config: Extraction configuration
        logger: Logger instance

    Returns:
        ExtractionResult with extracted URLs or error
    """
    result = ExtractionResult(source_url=js_url)

    # Fetch the content
    content, status_code, error = fetch_url(
        js_url,
        timeout=config.timeout,
        user_agent=config.user_agent,
        proxy=config.proxy,
        retries=config.retries
    )

    result.status_code = status_code

    if error:
        result.error = error
        return result

    if not content:
        result.error = "Empty response"
        return result

    # Extract URLs
    urls = extract_links_from_js(content)

    # Get scope from input URL
    parsed = urlparse(js_url)
    scope = parsed.netloc

    # Filter URLs
    filtered_urls = filter_urls(
        urls,
        scope,
        contain_equals=config.contain_equals,
        js_json_only=config.js_json_only,
        include_subdomains=config.include_subdomains
    )

    result.extracted_urls = filtered_urls
    return result

# ============================================================================
# Output Functions
# ============================================================================

def write_results_txt(
    results: List[ExtractionResult],
    output_file: str,
    deduplicate: bool = True
) -> int:
    """Write results to text file."""
    all_urls: Set[str] = set()

    # Collect all URLs
    for result in results:
        all_urls.update(result.extracted_urls)

    # Read existing URLs if file exists
    existing_urls: Set[str] = set()
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                existing_urls = set(line.strip() for line in f if line.strip())
        except IOError:
            pass

    # Calculate new URLs
    if deduplicate:
        new_urls = all_urls - existing_urls
    else:
        new_urls = all_urls

    # Append new URLs
    if new_urls:
        with open(output_file, 'a', encoding='utf-8') as f:
            for url in sorted(new_urls):
                f.write(url + '\n')

    return len(new_urls)

def write_results_json(
    results: List[ExtractionResult],
    output_file: str
) -> int:
    """Write results to JSON file."""
    output_data = {
        "total_sources": len(results),
        "successful": sum(1 for r in results if not r.error),
        "failed": sum(1 for r in results if r.error),
        "total_urls_found": sum(len(r.extracted_urls) for r in results),
        "results": []
    }

    all_urls: Set[str] = set()

    for result in results:
        result_dict = {
            "source": result.source_url,
            "status_code": result.status_code,
            "urls_found": len(result.extracted_urls),
            "urls": result.extracted_urls,
        }
        if result.error:
            result_dict["error"] = result.error
        output_data["results"].append(result_dict)
        all_urls.update(result.extracted_urls)

    output_data["unique_urls"] = sorted(all_urls)
    output_data["unique_url_count"] = len(all_urls)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

    return len(all_urls)

# ============================================================================
# Main Application
# ============================================================================

def run_extraction(config: Config, logger: logging.Logger) -> List[ExtractionResult]:
    """
    Run the URL extraction process.

    Args:
        config: Extraction configuration
        logger: Logger instance

    Returns:
        List of extraction results
    """
    # Collect URLs to process
    js_urls: List[str] = []

    if config.single_url:
        js_urls.append(config.single_url)
    elif config.input_file:
        try:
            with open(config.input_file, 'r', encoding='utf-8') as f:
                js_urls = [line.strip() for line in f if line.strip()]
        except IOError as e:
            logger.error(f"Failed to read input file: {e}")
            return []

    if not js_urls:
        logger.warning("No URLs to process")
        return []

    logger.info(f"Processing {len(js_urls)} URL(s)...")

    results: List[ExtractionResult] = []

    # Process with threading if multiple URLs
    if len(js_urls) > 1 and config.threads > 1:
        with ThreadPoolExecutor(max_workers=config.threads) as executor:
            futures = {}
            for i, url in enumerate(js_urls):
                if config.delay > 0 and i > 0:
                    time.sleep(config.delay)
                future = executor.submit(process_single_url, url, config, logger)
                futures[future] = url

            for future in as_completed(futures):
                result = future.result()
                results.append(result)

                if not config.silent:
                    if result.error:
                        logger.error(f"Failed: {result.source_url} - {result.error}")
                    else:
                        logger.info(
                            f"Extracted {len(result.extracted_urls)} URLs from {result.source_url}"
                        )
                        if config.verbose and result.extracted_urls:
                            for url in result.extracted_urls:
                                print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {url}")
    else:
        # Sequential processing
        for i, url in enumerate(js_urls):
            if config.delay > 0 and i > 0:
                time.sleep(config.delay)

            result = process_single_url(url, config, logger)
            results.append(result)

            if not config.silent:
                if result.error:
                    logger.error(f"Failed: {result.source_url} - {result.error}")
                else:
                    logger.info(
                        f"Extracted {len(result.extracted_urls)} URLs from {result.source_url}"
                    )
                    if config.verbose and result.extracted_urls:
                        for extracted_url in result.extracted_urls:
                            if config.no_color:
                                print(f"  [+] {extracted_url}")
                            else:
                                print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {extracted_url}")

    return results

def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Extract URLs from JavaScript files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -l urls.txt -o results.txt
  %(prog)s --url https://example.com/app.js -v
  %(prog)s -l urls.txt -p -j --threads 10
  %(prog)s --url https://example.com/app.js --include-subdomains
        """
    )

    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        '-l', '--input-file',
        dest='input_file',
        help='File containing list of JS URLs (one per line)'
    )
    input_group.add_argument(
        '--url',
        dest='single_url',
        help='Single JavaScript URL to process'
    )

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        dest='output_file',
        default=DEFAULT_OUTPUT_FILE,
        help=f'Output file path (default: {DEFAULT_OUTPUT_FILE})'
    )
    output_group.add_argument(
        '-f', '--format',
        dest='output_format',
        choices=['txt', 'json'],
        default='txt',
        help='Output format (default: txt)'
    )

    # Filter options
    filter_group = parser.add_argument_group('Filter Options')
    filter_group.add_argument(
        '-p', '--params-only',
        dest='contain_equals',
        action='store_true',
        help='Only extract URLs containing "=" (parameters)'
    )
    filter_group.add_argument(
        '-j', '--js-json-only',
        dest='js_json_only',
        action='store_true',
        help='Only extract URLs ending with .js or .json'
    )
    filter_group.add_argument(
        '-s', '--include-subdomains',
        dest='include_subdomains',
        action='store_true',
        help='Include all subdomains of the base domain'
    )

    # Request options
    request_group = parser.add_argument_group('Request Options')
    request_group.add_argument(
        '-t', '--timeout',
        dest='timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})'
    )
    request_group.add_argument(
        '-d', '--delay',
        dest='delay',
        type=float,
        default=DEFAULT_DELAY,
        help=f'Delay between requests in seconds (default: {DEFAULT_DELAY})'
    )
    request_group.add_argument(
        '--threads',
        dest='threads',
        type=int,
        default=DEFAULT_THREADS,
        help=f'Number of concurrent threads (default: {DEFAULT_THREADS})'
    )
    request_group.add_argument(
        '-r', '--retries',
        dest='retries',
        type=int,
        default=DEFAULT_RETRIES,
        help=f'Number of retries for failed requests (default: {DEFAULT_RETRIES})'
    )
    request_group.add_argument(
        '-A', '--user-agent',
        dest='user_agent',
        default=DEFAULT_USER_AGENT,
        help='Custom User-Agent header'
    )
    request_group.add_argument(
        '-x', '--proxy',
        dest='proxy',
        help='Proxy URL (e.g., http://127.0.0.1:8080)'
    )

    # Output control
    display_group = parser.add_argument_group('Display Options')
    display_group.add_argument(
        '--silent',
        action='store_true',
        help='Suppress all output except errors'
    )
    display_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show extracted URLs in console output'
    )
    display_group.add_argument(
        '--no-color',
        dest='no_color',
        action='store_true',
        help='Disable colored output'
    )
    display_group.add_argument(
        '--no-banner',
        dest='no_banner',
        action='store_true',
        help='Do not display banner'
    )

    # Misc
    parser.add_argument(
        '-V', '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )

    args = parser.parse_args()

    # Validate input
    if not args.single_url and not args.input_file:
        parser.error("Please provide either --url or -l/--input-file")

    if args.single_url and args.input_file:
        parser.error("Please provide either --url or -l/--input-file, not both")

    # Setup logging
    logger = setup_logging(verbose=args.verbose, no_color=args.no_color)

    # Display banner
    if not args.silent and not args.no_banner:
        clear_screen()
        print_banner(args.no_color)
        print()

    # Build config
    config = Config(
        input_file=args.input_file,
        output_file=args.output_file,
        single_url=args.single_url,
        silent=args.silent,
        contain_equals=args.contain_equals,
        js_json_only=args.js_json_only,
        timeout=args.timeout,
        delay=args.delay,
        threads=args.threads,
        retries=args.retries,
        user_agent=args.user_agent,
        proxy=args.proxy,
        include_subdomains=args.include_subdomains,
        output_format=args.output_format,
        no_color=args.no_color,
        verbose=args.verbose,
    )

    # Run extraction
    results = run_extraction(config, logger)

    if not results:
        return 1

    # Write output
    if config.output_format == 'json':
        count = write_results_json(results, config.output_file)
    else:
        count = write_results_txt(results, config.output_file)

    # Summary
    successful = sum(1 for r in results if not r.error)
    failed = sum(1 for r in results if r.error)
    total_urls = sum(len(r.extracted_urls) for r in results)

    if not config.silent:
        print()
        logger.info(f"Processed: {successful} successful, {failed} failed")
        logger.info(f"Total URLs extracted: {total_urls}")
        logger.info(f"Unique URLs written to {config.output_file}: {count}")

    return 0 if successful > 0 else 1


# ============================================================================
# Signal Handling
# ============================================================================

def signal_handler(sig: int, frame: Any) -> None:
    """Handle interrupt signal gracefully."""
    print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Interrupted by user. Exiting...")
    sys.exit(130)


if __name__ == "__main__":
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)

    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Interrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Unexpected error: {e}")
        sys.exit(1)
