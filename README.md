# DNS157 - Advanced DNS Recon Tool

## Description

**DNS157** is an advanced subdomain reconnaissance and DNS enumeration tool. It integrates various tools like `subfinder`, `amass`, `sublist3r`, `dnsx`, `httpx`, `dnsrecon`, `dnsenum`, `dig`, and `subjack` to identify subdomains, validate DNS resolutions, and detect potential takeover vulnerabilities.

Project URL: [DNS157 - Advanced DNS Recon Tool](https://github.com/rafaelcorvino1/DNS157---Advanced-DNS-Recon-Tool)

## Features

- Passive and active subdomain enumeration using `subfinder`, `amass`, and `sublist3r`.
- Validation of active subdomains via `dnsx` or `httpx`.
- Wildcard DNS detection to filter false positives.
- `subjack` for Subdomain Takeover vulnerability detection.
- Enumeration of DNS records (AXFR, SOA, NS, TXT, MX, CNAME, SRV).
- Collection of DNS resolution information using `dnsrecon` and `dnsenum`.
- Comparison of DNS responses across different public resolvers.
- Generates detailed reports in TXT and JSON formats.

## Installation

### Clone Repository

```bash
git clone https://github.com/rafaelcorvino1/DNS157---Advanced-DNS-Recon-Tool.git
cd DNS157
```

### Python Requirements & Dependencies

DNS157 requires **Python 3.6+**. Install the necessary Python module:

```bash
pip3 install --upgrade pip
pip3 install requests
```

### Required External Tools

- `dig` (included in `bind9-dnsutils` package)
- `subfinder` – [GitHub](https://github.com/projectdiscovery/subfinder)
- `amass` – [GitHub](https://github.com/OWASP/Amass)
- `sublist3r` – [GitHub](https://github.com/aboul3la/Sublist3r)
- `dnsx` – [GitHub](https://github.com/projectdiscovery/dnsx)
- `httpx` – [GitHub](https://github.com/projectdiscovery/httpx)
- `subjack` – [GitHub](https://github.com/haccer/subjack)
- `dnsrecon` – [GitHub](https://github.com/darkoperator/dnsrecon)
- `dnsenum` – [GitHub](https://github.com/fwaeytens/dnsenum)

#### Quick Installation on Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip bind9-dnsutils amass dnsrecon dnsenum git
```

For Go-based tools, install Go and follow the individual installation instructions:

```bash
sudo apt-get install -y golang-go
```

An automated installation script (`install.sh`) will be provided in the future.

## Usage

Run DNS157 from the command line:

```bash
python3 DNS157.py <domain> [--timeout <seconds>] [--subjack-fp <path>] [--crtsh]
```

### Options

- `<domain>`  
  Target domain (example: `example.com`).

- `--timeout <seconds>`  
  Timeout for each external command (default: 600 seconds).

- `--subjack-fp <path>`  
  Path to `fingerprints.json` file for Subjack (default: `/etc/subjack/fingerprints.json`).

- `--crtsh`  
  Enables querying [crt.sh](https://crt.sh) for additional subdomains.

### Examples

- **Display help:**

  ```bash
  python3 DNS157.py -h
  ```

- **Basic domain scan:**

  ```bash
  python3 DNS157.py example.com --crtsh
  ```

- **Custom timeout and fingerprint file path:**

  ```bash
  python3 example.com --timeout 900 --subjack-fp /path/to/fingerprints.json
  ```

## Techniques Used

### Subdomain Enumeration
- `subfinder`: Collects subdomains passively from online sources.
- `amass`: Uses OSINT methods to gather subdomains.
- `sublist3r`: Retrieves subdomains using search engines and services like Netcraft and VirusTotal.
- `crt.sh` Query: Fetches subdomains from SSL certificate transparency logs.
- Wildcard Detection: Identifies wildcard DNS and filters out false positives.

### Subdomain Validation
- `dnsx` / `httpx`: Verifies that enumerated subdomains resolve correctly via DNS.

### Takeover Detection
- `subjack`: Detects subdomain takeover vulnerable by comparing DNS responses against service fingerprints.

### Advanced DNS Reconnaissance
- `dnsrecon`: Performs zone transfers (AXFR), standard DNS queries, and DNSSEC zonewalks.
- `dnsenum`: Complements DNS enumeration and generates XML reports.

### Additional DNS Record Analysis
- `dig`: Queries A, CNAME, NS, SOA, SRV, CAA, MX, and TXT records.
- Reverse DNS: Retrieves PTR records for identified IPs.
- TTL Analysis: Computes average TTL values for caching insights.
- Resolver Comparison: Compares DNS responses from Google, Cloudflare, OpenDNS, and Quad9.

## License

DNS157 is licensed under the [MIT License](LICENSE).

## Credits

- **DNS157:** Developed to integrate multiple DNS reconnaissance techniques into a robust tool.
- **Inspiration:** Based on open-source projects such as Subfinder, Amass, Sublist3r, and others.

## Version

**Current version:** 1.1
