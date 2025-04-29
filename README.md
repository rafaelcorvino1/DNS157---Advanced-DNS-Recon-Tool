
# DNS157 - Advanced DNS Reconnaissance Tool


https://github.com/user-attachments/assets/06eeaf26-aad2-465f-8b99-e0b2b56bb13e


## Overview

**DNS157** is an advanced DNS reconnaissance tool designed for offensive security professionals. It automates subdomain enumeration, validation, and DNS analysis by integrating multiple open-source tools into a single streamlined framework. Its goal is to provide a precise and comprehensive view of the DNS attack surface for a target domain.

## Features

- Subdomain enumeration (`subfinder`, `amass`, `sublist3r`, `crt.sh`)
- Active subdomain validation using `dnsx` or `httpx`
- Wildcard DNS detection to eliminate false positives
- Subdomain takeover detection using `subjack`
- DNS record collection: A, NS, SOA, MX, TXT, CNAME, SRV, CAA
- DNS enumeration using `dnsrecon` and `dnsenum` (AXFR, zonewalk, standard)
- TTL analysis of A records
- Public resolver comparison (Google, Cloudflare, OpenDNS, Quad9)
- Structured reporting in TXT and JSON formats

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/rafaelcorvino1/DNS157.git
cd DNS157
```

### 2. Install Go and Go-based tools

```bash
sudo apt install -y golang-go
```

### 3. Install all required tools and ensure they are available in the system's PATH

Manually install the following tools from their official repositories:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [amass](https://github.com/OWASP/Amass)
- [sublist3r](https://github.com/aboul3la/Sublist3r)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [httpx](https://github.com/projectdiscovery/httpx)
- [subjack](https://github.com/haccer/subjack)

An automated installation script (`install.sh`) will be released soon. This script will install all required dependencies and configure the necessary tools within the system's PATH environment variable.


## Note on API Key Usage

Some of the integrated tools, such as `subfinder` and `amass`, support the use of API keys from third-party services (e.g., VirusTotal, SecurityTrails, Shodan, Censys, among others).

Configuring valid API keys significantly improves enumeration results by:

- Expanding the number of discovered subdomains
- Accessing premium data sources not available to unauthenticated users
- Reducing query rate limits imposed by public endpoints

It is strongly recommended to configure API keys in the corresponding tool settings to maximize the effectiveness and coverage of DNS157 reconnaissance operations.

Refer to each tool's official documentation for instructions on how to configure and use API keys.

## Usage

### Basic execution

```bash
python3 DNS157.py <domain>
```

## Techniques Used

### Subdomain Enumeration

- `subfinder`: passive subdomain discovery from online sources
- `amass`: OSINT-based subdomain discovery
- `sublist3r`: search engine-based enumeration
- `crt.sh`: retrieval from SSL certificate transparency logs
- Wildcard DNS detection and false positive filtering

### Subdomain Validation

- `dnsx` or `httpx`: DNS resolution validation of discovered subdomains

### Subdomain Takeover Detection

- `subjack`: detection of subdomain takeover vulnerabilities using fingerprint matching

### Advanced DNS Reconnaissance

- `dnsrecon`: zone transfer (AXFR), standard enumeration, and DNSSEC zonewalk
- `dnsenum`: complementary enumeration and XML reporting

### Additional DNS Analysis

- `dig`: retrieval of A, CNAME, NS, SOA, TXT, MX, SRV, and CAA records
- Reverse DNS: PTR record collection for identified IP addresses
- TTL analysis: average TTL calculation per subdomain
- Resolver comparison: cross-referencing responses from Google (8.8.8.8), Cloudflare (1.1.1.1), OpenDNS (208.67.222.222), and Quad9 (9.9.9.9)

## Reports

DNS157 generates the following reports:

- `final_report.txt`: detailed technical report covering all reconnaissance phases
- `report.json`: structured data report for automated parsing and analysis

All reports are saved within a directory named after the analyzed domain.

## License

This project is licensed under the MIT License. Refer to the `LICENSE` file for further details.

## Credits

DNS157 was developed by Rafael Corvino and is based on the integration of various widely adopted open-source reconnaissance tools.

## Version

Current version: 1.2
Last updated: April 2025
