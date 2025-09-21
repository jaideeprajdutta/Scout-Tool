# SCOUT CLI Tool
SCOUT is a simple, beginner-friendly CLI tool for passive reconnaissance and basic takeover checks. It helps you discover subdomains, check for wildcard DNS, and identify potential takeover risks. Features include fetching subdomains via crt.sh, detecting wildcard DNS, resolving A and CNAME records, HTTP probing, basic takeover checks for GitHub Pages, AWS S3, Heroku, Netlify, and Azure Blob, and saving results in JSON, CSV, and Markdown formats. 

## Installation
Clone the repo:
git clone https://github.com/jaideeprajdutta/Scout-Tool.git
cd Scout-Tool

Create a virtual environment (recommended):
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux/macOS

Install dependencies:
pip install -r requirements.txt

(Optional) Install SCOUT as a CLI command:
pip install -e .

Now you can run:
scout scan example.com -o scout_output

## Usage
scout scan <domain> [-w <wordlist>] [-o <outfile>] [--threads <num>]
- <domain>: The domain you have permission to scan
- -w: Optional wordlist path
- -o: Base name for output files
- --threads: Number of concurrent threads (default: 30)

Example:
scout scan example.com -o scout_output

Results will be saved as scout_output.json, scout_output.csv, and scout_output.md.



