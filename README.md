SCOUT CLI Tool

SCOUT CLI Tool is a passive reconnaissance and basic takeover check tool designed for ethical hacking and cybersecurity enthusiasts. It supports subdomain enumeration using crt.sh and common wordlists, wildcard detection, CNAME resolution, basic HTTP probing, and detection of potential subdomain takeover risks. The tool generates outputs in JSON, CSV, and Markdown formats.

Installation

Clone the repository from GitHub and navigate into the folder. Create a Python virtual environment using python -m venv venv and activate it. Install dependencies by running pip install -r requirements.txt. Install SCOUT as a CLI tool using pip install -e .. Verify installation by running scout --help.

Usage

Run a scan on a domain you own or have permission to test: scout scan example.com -o scout_output. This will generate scout_output.json, scout_output.csv, and scout_output.md in the current folder.

Optional flags include --wordlist <path> to specify a custom subdomain wordlist and --threads <number> to adjust concurrency for faster scanning.

License

SCOUT was created by Jaideep Raj Dutta and is licensed under the MIT License.
