# URL Extractor

A Python tool to extract URLs from JavaScript files. It supports filtering URLs based on domain, file extensions, and specific content (e.g., URLs containing `=`). It can process a list of URLs from a file or a single JavaScript URL.

## Features

- **Extract URLs** from JavaScript files.
- **Filter URLs** based on domain, file extensions (.js, .json), and whether they contain the `=` character.
- Supports **batch processing** with a list of URLs or a single URL.
- **Silent mode** for minimal output, displaying only progress without detailed logs.

## Prerequisites

- Python 3.x
- `requests` library
- `colorama` library

You can install the required dependencies by running:

```bash
pip install -r requirements.txt
```

## Installation

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/your-username/url-extractor.git
   ```

2. Navigate into the project directory:
   ```bash
   cd url-extractor
   ```

3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Extract URLs from a List of JavaScript URLs

To extract URLs from a list of JavaScript URLs in a file:

```bash
python3 url_extractor.py -l urls.txt -o extracted_links.txt
```

- `-l` : Path to the input file containing a list of JavaScript URLs (one URL per line).
- `-o` : Path to the output file where the extracted URLs will be saved (default is `extracted_links.txt`).

### Extract URLs from a Single JavaScript URL

To extract URLs from a single JavaScript URL:

```bash
python3 url_extractor.py --url http://example.com/script.js -o extracted_links.txt
```

- `--url` : Single JavaScript URL to process.
- `-o` : Path to the output file where the extracted URLs will be saved.

### Additional Options

- `--silent` : Suppress detailed output and show only the processed count.
- `-p` or `--contains_equals` : Only extract URLs that contain `=` ( parameters ).  
- `-j` or `--js_json_only` : Only extract URLs ending with `.js` or `.json`.


