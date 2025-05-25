# ReconSuite

A comprehensive web reconnaissance tool that automates and streamlines the entire recon process.

## Features

- **DNS Reconnaissance**: Query DNS records to map network infrastructure
- **WHOIS Lookup**: Gather domain registration information
- **Subdomain Enumeration**: Discover subdomains of the target domain
- **Port Scanning**: Identify open ports and running services
- **Directory Discovery**: Find hidden directories and files
- **Vulnerability Scanning**: Basic vulnerability detection
- **HTTP Header Analysis**: Check for security headers and misconfigurations
- **Technology Stack Detection**: Identify technologies used by the target

## Installation

### Prerequisites

- Python 3.11 or newer
- pip (Python package manager)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/reconsuite.git
   cd reconsuite
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python main.py
   ```

5. Access the application in your browser at: http://localhost:5000

## Usage

1. Navigate to the home page and click "Start New Scan"
2. Enter a target domain and select the reconnaissance modules to run
3. View and analyze the results in the interactive dashboard

## Ethical Guidelines

This tool is designed for security professionals and ethical hackers. Please adhere to the following guidelines:

- Only scan targets that you own or have explicit permission to test
- Be aware of and adhere to all applicable laws and regulations
- If you discover vulnerabilities, report them responsibly
- Be mindful of the impact your scanning may have on target resources

## License

This project is licensed under the MIT License - see the LICENSE file for details.