#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import shutil
import re
import random
import string
import json
import logging
import requests
from datetime import datetime

DEFAULT_TIMEOUT = 600

def print_banner():
    banner = r'''
                                                                                      
88888888ba,    888b      88   ad88888ba          88     8888888888      888888888888  
88      `"8b   8888b     88  d8"     "8b       ,d88     88                      ,8P'  
88        `8b  88 `8b    88  Y8,             888888     88  ____               d8"    
88         88  88  `8b   88  `Y8aaaaa,           88     88a8PPPP8b,          ,8P'     
88         88  88   `8b  88    `"""""8b,         88     PP"     `8b         d8"       
88         8P  88    `8b 88          `8b         88              d8       ,8P'        
88      .a8P   88     `8888  Y8a     a8P         88     Y8a     a8P      d8"          
88888888Y"'    88      `888   "Y88888P"          88      "Y88888P"      8P'           
                                                                                      
    '''
    print(banner)

def setup_logging(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8")
        ]
    )

def run_cmd(command, output_file=None, timeout=DEFAULT_TIMEOUT):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        stdout = result.stdout.strip()
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(stdout + "\n")
        return stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {' '.join(e.cmd)} - Error: {e.stderr.strip()}")
        return ""
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return ""

def validate_domain(domain):
    domain_pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
    if not re.match(domain_pattern, domain):
        logging.error("Invalid domain.")
        sys.exit(1)

def detect_wildcard_dns(domain, timeout=DEFAULT_TIMEOUT):
    rand_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    test_subdomain = f"{rand_sub}.{domain}"
    out = run_cmd(["dig", "+short", test_subdomain], timeout=timeout)
    return (bool(out.strip()), test_subdomain)

def discover_subdomains(domain, output_dir, wildcard_detected, test_subdomain, timeout=DEFAULT_TIMEOUT):
    subfinder_out = os.path.join(output_dir, "subfinder.txt")
    amass_out = os.path.join(output_dir, "amass.txt")
    sublist3r_out = os.path.join(output_dir, "sublist3r.txt")
    raw_out = os.path.join(output_dir, "subdomains_raw.txt")
    final_subs = set()

    if shutil.which("subfinder"):
        logging.info("Running Subfinder...")
        sf = run_cmd(["subfinder", "-silent", "-d", domain], timeout=timeout)
        if sf:
            with open(subfinder_out, "w", encoding="utf-8") as f:
                f.write(sf + "\n")
            final_subs.update(sf.splitlines())
    else:
        logging.warning("subfinder not found.")

    if shutil.which("amass"):
        logging.info("Running Amass...")
        am = run_cmd(["amass", "enum", "-passive", "-d", domain], timeout=timeout)
        if am:
            with open(amass_out, "w", encoding="utf-8") as f:
                f.write(am + "\n")
            final_subs.update(am.splitlines())
    else:
        logging.warning("amass not found.")

    if shutil.which("sublist3r"):
        logging.info("Running Sublist3r...")
        try:
            subprocess.run(
                ["sublist3r", "-d", domain, "-o", sublist3r_out],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout
            )
        except Exception as e:
            logging.error(f"Sublist3r failed: {str(e)}")
        if os.path.isfile(sublist3r_out):
            with open(sublist3r_out, "r", encoding="utf-8") as f:
                final_subs.update(line.strip() for line in f if line.strip())
    else:
        logging.warning("sublist3r not found.")

    if args.crtsh:
        logging.info("Querying crt.sh for additional subdomains...")
        crt_subs = query_crtsh(domain, timeout)
        final_subs.update(crt_subs)

    with open(raw_out, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(final_subs)))

    if wildcard_detected:
        logging.info("Filtering wildcard DNS...")
        wildcard_ips = set(run_cmd(["dig", "+short", test_subdomain], timeout=timeout).splitlines())
        verified_subs = set()
        for sub in final_subs:
            sub_ips = set(run_cmd(["dig", "+short", sub], timeout=timeout).splitlines())
            if sub_ips and sub_ips != wildcard_ips:
                verified_subs.add(sub)
        return verified_subs

    return final_subs

def validate_subdomains(subdomains, output_dir, timeout=DEFAULT_TIMEOUT):
    valid_file = os.path.join(output_dir, "subdomains_valid.txt")
    if not subdomains:
        open(valid_file, "w").close()
        return []
    tmp_list = os.path.join(output_dir, "temp_subs.txt")
    with open(tmp_list, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(subdomains)))
    if shutil.which("dnsx"):
        logging.info("Validating with DNSx...")
        run_cmd(["dnsx", "-silent", "-resp", "-l", tmp_list, "-o", valid_file], timeout=timeout)
    elif shutil.which("httpx"):
        logging.info("Validating with HTTPx...")
        run_cmd(["httpx", "-silent", "-l", tmp_list, "-o", valid_file], timeout=timeout)
    else:
        shutil.copy(tmp_list, valid_file)
    valid_subs = []
    if os.path.isfile(valid_file):
        with open(valid_file, "r", encoding="utf-8") as vf:
            valid_subs = [line.strip() for line in vf if line.strip()]
    if os.path.exists(tmp_list):
        os.remove(tmp_list)
    return valid_subs

def subdomain_takeover(valid_subs, output_dir, subjack_fp, timeout=DEFAULT_TIMEOUT):
    takefile = os.path.join(output_dir, "takeover_subjack.txt")
    vulns = os.path.join(output_dir, "takeover_vulnerable.txt")
    found = []
    if not valid_subs:
        open(takefile, "w").close()
        open(vulns, "w").close()
        return []
    tmp_list = os.path.join(output_dir, "temp_valsubs.txt")
    with open(tmp_list, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(valid_subs)))
    if shutil.which("subjack"):
        logging.info("Checking Subdomain Takeover with subjack...")
        if os.path.isfile(subjack_fp):
            run_cmd([
                "subjack",
                "-w", tmp_list,
                "-o", takefile,
                "-ssl",
                "-c", subjack_fp,
                "-t", "10",
                "-timeout", "10"
            ], timeout=300)
            if os.path.isfile(takefile):
                with open(takefile, "r", encoding="utf-8") as tf:
                    found = [line.strip() for line in tf if "Vulnerable" in line]
                with open(vulns, "w", encoding="utf-8") as vf:
                    vf.write("\n".join(found))
        else:
            logging.warning("Fingerprints file not found. Skipping subjack.")
            open(takefile, "w").close()
            open(vulns, "w").close()
    else:
        logging.warning("subjack not found.")
    if os.path.exists(tmp_list):
        os.remove(tmp_list)
    return found

def dns_enum(domain, output_dir, timeout=DEFAULT_TIMEOUT):
    axfr_out = os.path.join(output_dir, "dnsrecon_axfr.txt")
    std_out = os.path.join(output_dir, "dnsrecon_std.txt")
    dnssec_out = os.path.join(output_dir, "dnsrecon_zonewalk.txt")
    dnsenum_xml = os.path.join(output_dir, "dnsenum_output.xml")
    if shutil.which("dnsrecon"):
        logging.info("Running DNSRecon...")
        run_cmd(["dnsrecon", "-d", domain, "-t", "axfr"], axfr_out, timeout=300)
        run_cmd(["dnsrecon", "-d", domain, "-t", "std"], std_out, timeout=300)
        try:
            run_cmd(["dnsrecon", "-d", domain, "-t", "zonewalk"], dnssec_out, timeout=300)
        except Exception as e:
            logging.error("Zonewalk (DNSSEC) check failed.")
    else:
        logging.warning("dnsrecon not found.")
    if shutil.which("dnsenum"):
        logging.info("Running DNSEnum...")
        run_cmd(["dnsenum", "--enum", "-s", "0", "-p", "0", "--noreverse", "--nocolor", "-o", dnsenum_xml, domain], timeout=timeout)
    else:
        logging.warning("dnsenum not found.")
    return axfr_out, std_out, dnssec_out, dnsenum_xml

def parse_ips_from_axfr(axfr_file):
    ips = set()
    if not os.path.isfile(axfr_file):
        return ips
    ip_pattern = re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\."
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\."
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\."
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
    )
    with open(axfr_file, "r", encoding="utf-8") as f:
        content = f.read()
        matches = ip_pattern.findall(content)
        ips.update(matches)
    return ips

def reverse_dns_for_ranges(ips, output_dir, timeout=DEFAULT_TIMEOUT):
    out_file = os.path.join(output_dir, "reverse_dns.txt")
    if not ips:
        open(out_file, "w").close()
        return
    logging.info("Running Reverse DNS...")
    with open(out_file, "w", encoding="utf-8") as f:
        for ip in sorted(ips):
            rev_out = run_cmd(["dig", "+short", "-x", ip], timeout=timeout)
            ptr = rev_out.strip() if rev_out else "no_ptr_record"
            f.write(f"{ip} -> {ptr}\n")

def additional_dns_records(domain, output_dir, timeout=DEFAULT_TIMEOUT):
    extras_file = os.path.join(output_dir, "additional_dns.txt")
    results = []
    logging.info("Collecting additional DNS records...")
    for record_type in ["SRV", "CAA", "MX", "TXT"]:
        dig_out = run_cmd(["dig", "+short", record_type, domain], timeout=timeout)
        if dig_out.strip():
            results.append(f"{record_type}:\n{dig_out}\n{'-'*50}")
    with open(extras_file, "w", encoding="utf-8") as f:
        f.write("\n".join(results))

def query_crtsh(domain, timeout=DEFAULT_TIMEOUT):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                names = entry.get("name_value", "").splitlines()
                for name in names:
                    name = name.lstrip("*.").strip()
                    if name.endswith(domain):
                        subs.add(name)
        else:
            logging.warning(f"Error querying crt.sh: HTTP {response.status_code}")
    except Exception as e:
        logging.error(f"Error querying crt.sh: {e}")
    return subs

def normalize_subdomains(subdomains):
    normalized = set()
    for sub in subdomains:
        norm = sub.lower().rstrip('.')
        normalized.add(norm)
    return normalized

def analyze_cnames(valid_subs, output_dir, timeout=DEFAULT_TIMEOUT):
    cname_file = os.path.join(output_dir, "cname_records.txt")
    results = {}
    logging.info("Analyzing CNAME records...")
    for sub in valid_subs:
        output = run_cmd(["dig", "+short", "CNAME", sub], timeout=timeout)
        if output:
            results[sub] = output.strip().splitlines()
    with open(cname_file, "w", encoding="utf-8") as f:
        for sub, cnames in results.items():
            f.write(f"{sub}:\n")
            for cname in cnames:
                f.write(f"  {cname}\n")
            f.write("\n")

def compare_resolvers(valid_subs, output_dir, timeout=DEFAULT_TIMEOUT):
    resolvers = {
       "Google": "8.8.8.8",
       "Cloudflare": "1.1.1.1",
       "OpenDNS": "208.67.222.222",
       "Quad9": "9.9.9.9"
    }
    comp_file = os.path.join(output_dir, "resolver_comparison.txt")
    logging.info("Comparing responses using multiple resolvers...")
    with open(comp_file, "w", encoding="utf-8") as f:
        for sub in sorted(valid_subs):
            f.write(f"Subdomain: {sub}\n")
            for name, resolver in resolvers.items():
                output = run_cmd(["dig", f"@{resolver}", "+short", sub], timeout=timeout)
                response = output.strip() if output else "No response"
                f.write(f"  {name} ({resolver}): {response}\n")
            f.write("\n")

def check_ns_soa(valid_subs, output_dir, timeout=DEFAULT_TIMEOUT):
    ns_file = os.path.join(output_dir, "ns_records.txt")
    soa_file = os.path.join(output_dir, "soa_records.txt")
    ns_results = {}
    soa_results = {}
    logging.info("Collecting NS and SOA records...")
    for sub in valid_subs:
        ns_output = run_cmd(["dig", "+short", "NS", sub], timeout=timeout)
        if ns_output:
            ns_results[sub] = ns_output.strip().splitlines()
        soa_output = run_cmd(["dig", "+short", "SOA", sub], timeout=timeout)
        if soa_output:
            soa_results[sub] = soa_output.strip().splitlines()
    with open(ns_file, "w", encoding="utf-8") as f:
        for sub, records in ns_results.items():
            f.write(f"{sub}:\n")
            for rec in records:
                f.write(f"  {rec}\n")
            f.write("\n")
    with open(soa_file, "w", encoding="utf-8") as f:
        for sub, records in soa_results.items():
            f.write(f"{sub}:\n")
            for rec in records:
                f.write(f"  {rec}\n")
            f.write("\n")

def analyze_ttl(valid_subs, output_dir, timeout=DEFAULT_TIMEOUT):
    ttl_file = os.path.join(output_dir, "ttl_analysis.txt")
    logging.info("Analyzing TTL of A records...")
    with open(ttl_file, "w", encoding="utf-8") as f:
        for sub in sorted(valid_subs):
            output = run_cmd(["dig", "+noall", "+answer", sub, "A"], timeout=timeout)
            if output:
                lines = output.splitlines()
                ttls = []
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        try:
                            ttl = int(parts[1])
                            ttls.append(ttl)
                        except ValueError:
                            continue
                if ttls:
                    average_ttl = sum(ttls) / len(ttls)
                    f.write(f"{sub}: TTLs = {ttls}, Average TTL = {average_ttl:.2f}\n")
                else:
                    f.write(f"{sub}: No TTL information.\n")
            else:
                f.write(f"{sub}: No A record found.\n")

def generate_report(domain, output_dir, raw_subs, valid_subs, takeovers, axfr, std, dnssec_file, dnsenum_xml):
    add_dns = os.path.join(output_dir, "additional_dns.txt")
    rev_dns = os.path.join(output_dir, "reverse_dns.txt")
    takeover_vuln = os.path.join(output_dir, "takeover_vulnerable.txt")
    txt_report = os.path.join(output_dir, "final_report.txt")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = "=" * 60
    divider = "-" * 60
    with open(txt_report, "w", encoding="utf-8") as rf:
        rf.write(f"{header}\n")
        rf.write("DNS157 - Final DNS Recon Report\n")
        rf.write(f"Date/Time: {now}\n")
        rf.write(f"{header}\n\n")
        rf.write("1. General Information\n")
        rf.write(f"{divider}\n")
        rf.write(f"Target Domain          : {domain}\n")
        rf.write(f"Raw Subdomains         : {len(raw_subs)}\n")
        rf.write(f"Validated Subdomains   : {len(valid_subs)}\n\n")
        rf.write("2. Identified Raw Subdomains\n")
        rf.write(f"{divider}\n")
        if raw_subs:
            rf.write("\n".join(sorted(raw_subs)) + "\n")
        else:
            rf.write("No subdomains found.\n")
        rf.write("\n")
        rf.write("3. Validated Subdomains (Confirmed DNS Response)\n")
        rf.write(f"{divider}\n")
        if valid_subs:
            rf.write("\n".join(sorted(valid_subs)) + "\n")
        else:
            rf.write("No subdomains validated.\n")
        rf.write("\n")
        rf.write("4. Potential Subdomain Takeover Vulnerabilities\n")
        rf.write(f"{divider}\n")
        if os.path.isfile(takeover_vuln) and os.path.getsize(takeover_vuln) > 0:
            with open(takeover_vuln, "r", encoding="utf-8") as tv:
                rf.write(tv.read() + "\n")
        else:
            rf.write("No takeover vulnerabilities identified.\n")
        rf.write("\n")
        rf.write("5. DNSRecon Results\n")
        rf.write(f"{divider}\n")
        sections = [("AXFR", axfr), ("STD", std), ("Zonewalk (DNSSEC)", dnssec_file)]
        for name, file_path in sections:
            rf.write(f"5. {name}:\n")
            rf.write(f"{divider}\n")
            if os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
                with open(file_path, "r", encoding="utf-8") as sf:
                    rf.write(sf.read() + "\n")
            else:
                rf.write("No results.\n")
            rf.write(f"{divider}\n\n")
        rf.write("6. Reverse DNS\n")
        rf.write(f"{divider}\n")
        if os.path.isfile(rev_dns) and os.path.getsize(rev_dns) > 0:
            with open(rev_dns, "r", encoding="utf-8") as rv:
                rf.write(rv.read() + "\n")
        else:
            rf.write("No reverse DNS records found.\n")
        rf.write("\n")
        rf.write("7. Additional DNS Records (SRV, CAA, MX, TXT)\n")
        rf.write(f"{divider}\n")
        if os.path.isfile(add_dns) and os.path.getsize(add_dns) > 0:
            with open(add_dns, "r", encoding="utf-8") as ad:
                rf.write(ad.read() + "\n")
        else:
            rf.write("No additional records collected.\n")
        rf.write("\n")
        rf.write(f"{header}\n")
        rf.write("End of Report\n")
        rf.write(f"{header}\n")
    json_report = os.path.join(output_dir, "report.json")
    report_data = {
        "domain": domain,
        "raw_subdomains": sorted(list(raw_subs)),
        "valid_subdomains": sorted(list(valid_subs)),
        "takeovers": [],
        "dnsrecon": {},
        "reverse_dns": {},
        "additional_dns": ""
    }
    if os.path.isfile(takeover_vuln):
        with open(takeover_vuln, "r", encoding="utf-8") as tv:
            report_data["takeovers"] = tv.read().splitlines()
    for section, file_path in [("DNSRecon AXFR", axfr), ("DNSRecon STD", std), ("DNSRecon Zonewalk", dnssec_file)]:
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding="utf-8") as sf:
                report_data["dnsrecon"][section] = sf.read()
    if os.path.isfile(rev_dns):
        with open(rev_dns, "r", encoding="utf-8") as rv:
            for line in rv.read().splitlines():
                parts = line.split(" -> ")
                if len(parts) == 2:
                    report_data["reverse_dns"][parts[0]] = parts[1]
    if os.path.isfile(add_dns):
        with open(add_dns, "r", encoding="utf-8") as ad:
            report_data["additional_dns"] = ad.read()
    with open(json_report, "w", encoding="utf-8") as jf:
        json.dump(report_data, jf, indent=4, ensure_ascii=False)

def main():
    global args, DEFAULT_TIMEOUT
    parser = argparse.ArgumentParser(description="DNS157 - DNS Recon")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--timeout", type=int, default=600, help="Default command timeout (seconds)")
    parser.add_argument("--subjack-fp", default="/etc/subjack/fingerprints.json", help="Path to subjack's fingerprints.json")
    parser.add_argument("--crtsh", action="store_true", help="Enable crt.sh query for additional subdomains")
    args = parser.parse_args()
    DEFAULT_TIMEOUT = args.timeout
    domain = args.domain.strip().lower()
    validate_domain(domain)
    output_dir = domain
    os.makedirs(output_dir, exist_ok=True)
    log_file_path = os.path.join(output_dir, "log.txt")
    setup_logging(log_file_path)
    
    print_banner()
    
    logging.info(f"Starting reconnaissance for: {domain}")
    wildcard_detected, test_subdomain = detect_wildcard_dns(domain, timeout=DEFAULT_TIMEOUT)
    logging.info(f"Wildcard DNS detected: {'Yes' if wildcard_detected else 'No'}")
    raw_subdomains = discover_subdomains(domain, output_dir, wildcard_detected, test_subdomain, timeout=DEFAULT_TIMEOUT)
    valid_subdomains = validate_subdomains(raw_subdomains, output_dir, timeout=DEFAULT_TIMEOUT)
    valid_subdomains = normalize_subdomains(valid_subdomains)
    takeovers = subdomain_takeover(valid_subdomains, output_dir, args.subjack_fp, timeout=DEFAULT_TIMEOUT)
    axfr_file, std_file, dnssec_file, dnsenum_xml = dns_enum(domain, output_dir, timeout=DEFAULT_TIMEOUT)
    ips = parse_ips_from_axfr(axfr_file)
    reverse_dns_for_ranges(ips, output_dir, timeout=DEFAULT_TIMEOUT)
    additional_dns_records(domain, output_dir, timeout=DEFAULT_TIMEOUT)
    analyze_cnames(valid_subdomains, output_dir, timeout=DEFAULT_TIMEOUT)
    compare_resolvers(valid_subdomains, output_dir, timeout=DEFAULT_TIMEOUT)
    check_ns_soa(valid_subdomains, output_dir, timeout=DEFAULT_TIMEOUT)
    analyze_ttl(valid_subdomains, output_dir, timeout=DEFAULT_TIMEOUT)
    generate_report(domain, output_dir, raw_subdomains, valid_subdomains, takeovers, axfr_file, std_file, dnssec_file, dnsenum_xml)
    logging.info("Completed!")
    report_file = os.path.join(output_dir, "final_report.txt")
    try:
        with open(report_file, "r", encoding="utf-8") as f:
            report_content = f.read()
        print("\n" + report_content)
    except Exception as e:
        logging.error(f"Error reading final_report.txt: {e}")

if __name__ == "__main__":
    main()
