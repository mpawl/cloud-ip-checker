#!/usr/bin/env python3

import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

import sys
import argparse
import json
import csv
import os
import shutil
import ipaddress
import urllib.request
from urllib.error import URLError, HTTPError
from typing import List, Dict, Any

# This is the directory inside of the current directory where data files will be stored.
DATA_DIR = "cloud_ip_data"

# Monitored providers and the URLs to download the data files. Microsoft data files are not currently
# automatable. Reference links are included, however following instructions in README is preferred.
PROVIDERS = {
    "azure": {
        "url": "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20250929.json",
        "filename": "azure.json"
    },
    "aws": {
        "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "filename": "aws.json"
    },
    "gcp": {
        "url": "https://www.gstatic.com/ipranges/cloud.json",
        "filename": "gcp.json"
    },
    "google": {
        "url": "https://www.gstatic.com/ipranges/goog.json",
        "filename": "google.json"
    },
    "oci": {
        "url": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
        "filename": "oci.json"
    },
    "do": {
        "url": "https://digitalocean.com/geo/google.csv",
        "filename": "digitalocean.csv"
    },
    "m365": {
        "url": "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7",
        "filename": "m365.json"
    }
}


class CloudIPChecker:
    def __init__(self, data_dir: str = DATA_DIR):
        self.data_dir = data_dir
        self.providers_data = {}

    def download_files(self, force: bool = False):
        os.makedirs(self.data_dir, exist_ok=True)
        for provider, meta in PROVIDERS.items():
            if meta["url"] is None:
                continue  # Handled manually
            path = os.path.join(self.data_dir, meta["filename"])
            if force or not os.path.exists(path):
                logging.info(f"Downloading {provider} data...")
                try:
                    request = urllib.request.Request(meta["url"], headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(request) as response, open(path, "wb") as out_file:
                        shutil.copyfileobj(response, out_file)
                except HTTPError as e:
                    logging.error(f"Failed to download {provider} data (HTTP {e.code}: {e.reason}).")
                    if os.path.exists(path):
                        os.remove(path)
                    continue
                except URLError as e:
                    logging.error(f"Failed to download {provider} data ({e.reason}).")
                    if os.path.exists(path):
                        os.remove(path)
                    continue
                except Exception as e:
                    logging.error(f"Unexpected error downloading {provider} data: {e}")
                    if os.path.exists(path):
                        os.remove(path)
                    continue
            else:
                logging.info(f"{provider} data already present.")

    def is_ip_address(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def load_data(self):
        for provider, meta in PROVIDERS.items():
            path = os.path.join(self.data_dir, meta["filename"])
            if not os.path.exists(path):
                continue
            try:
                if provider == "do":
                    with open(path, newline="") as f:
                        reader = csv.DictReader(
                            f,
                            fieldnames=["cidr", "country", "region", "city", "postal_code"],
                            restkey="extra",
                            restval=""
                        )
                        entries = []
                        for row in reader:
                            cidr = (row.get("cidr") or "").strip()
                            if not cidr or cidr.startswith("#"):
                                continue
                            normalized = {"cidr": cidr}
                            for key, value in row.items():
                                if key in (None, "cidr"):
                                    continue
                                if value is None:
                                    continue
                                if isinstance(value, list):
                                    value = ", ".join(
                                        v.strip() for v in value if isinstance(v, str) and v.strip()
                                    )
                                elif isinstance(value, str):
                                    value = value.strip()
                                else:
                                    value = str(value).strip()
                                if value:
                                    normalized[key.replace(" ", "_")] = value
                            entries.append(normalized)
                        self.providers_data[provider] = entries
                else:
                    with open(path, "r") as f:
                        self.providers_data[provider] = json.load(f)
            except FileNotFoundError:
                logging.error("File not found.")
                sys.exit(1)
            except json.JSONDecodeError:
                logging.error("Invalid JSON format.")
                sys.exit(1)
            except csv.Error:
                logging.error("Invalid CSV format.")
                sys.exit(1)

    def lookup_ip(self, ip: str) -> List[Dict[str, Any]]:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except:
            logging.info(f"{ip} is not a valid IP address.")
            sys.exit(1)
            
        results = []

        for provider, data in self.providers_data.items():
            if provider == "azure":
                for prefix_entry in data.get("values", []):
                    properties = prefix_entry.get("properties", {})
                    for prefix in properties.get("addressPrefixes", []):
                        if self._ip_in_cidr(ip_obj, prefix):
                            entry = {
                                "provider": "Azure",
                                "cidr": prefix,
                                "service": prefix_entry.get("name", "N/A")
                            }

                            # Include all keys except those explicitly excluded
                            exclude_keys = {"addressPrefixes", "ips"}
                            for key, value in properties.items():
                                if key not in exclude_keys:
                                    entry[key] = value
                            results.append(entry)

            elif provider == "aws":
                for prefix_entry in data.get("prefixes", []):
                    cidr = prefix_entry.get("ip_prefix")
                    if cidr and self._ip_in_cidr(ip_obj, cidr):
                        entry = {"provider": "AWS", "cidr": cidr}
                        entry.update(prefix_entry)
                        results.append(entry)
                for prefix_entry in data.get("ipv6_prefixes", []):
                    cidr = prefix_entry.get("ipv6_prefix")
                    if cidr and self._ip_in_cidr(ip_obj, cidr):
                        entry = {"provider": "AWS", "cidr": cidr}
                        entry.update(prefix_entry)
                        results.append(entry)

            elif provider in ("gcp", "google"):
                for prefix_entry in data.get("prefixes", []):
                    cidr = prefix_entry.get("ipv4Prefix") or prefix_entry.get("ipv6Prefix")
                    if cidr and self._ip_in_cidr(ip_obj, cidr):
                        entry = {
                            "provider": "GCP" if provider == "gcp" else "Google",
                            "cidr": cidr
                        }
                        entry.update(prefix_entry)
                        results.append(entry)

            elif provider == "do":
                for record in data:
                    cidr = record.get("cidr")
                    if cidr and self._ip_in_cidr(ip_obj, cidr):
                        match = {
                            "provider": "Digital Ocean",
                            "cidr": cidr
                        }
                        for key, value in record.items():
                            if key == "cidr" or not value:
                                continue
                            match[key] = value
                        results.append(match)

            elif provider == "oci":
                for region_entry in data.get("regions", []):
                    region_name = region_entry.get("region", "N/A")
                    for cidr_entry in region_entry.get("cidrs", []):
                        cidr = cidr_entry.get("cidr")
                        if cidr and self._ip_in_cidr(ip_obj, cidr):
                            entry = {
                                "provider": "OCI",
                                "region": region_name,
                                "cidr": cidr
                            }
                            entry.update(cidr_entry)
                            results.append(entry)

            elif provider == "m365":
                for entry in data:
                    for cidr in entry.get("ips", []):
                        if self._ip_in_cidr(ip_obj, cidr):
                            match = {
                                "provider": "M365",
                                "cidr": cidr,
                                "serviceArea": entry.get("serviceArea", "N/A"),
                                "serviceAreaDisplayName": entry.get("serviceAreaDisplayName", "N/A")
                            }
                            # Include all keys except those explicitly excluded
                            exclude_keys = {"required", "ips", "addressPrefixes"}
                            for key, value in entry.items():
                                if key not in exclude_keys:
                                    match[key] = value
                            results.append(match)


        return results
    
    def _ip_in_cidr(self, ip: ipaddress._BaseAddress, cidr: str) -> bool:
        try:
            return ip in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False


def main():
    # Set up command line options
    parser = argparse.ArgumentParser(description="Lookup cloud provider info for an IP address.")
    parser.add_argument('--ip', required=True, help="IP address to check")
    parser.add_argument('--force-download', action='store_true', help="Force re-download of cloud IP data")
    args = parser.parse_args()

    checker = CloudIPChecker()

    # Sanitize and Verify that input is an IP. Quit if not.
    args.ip = args.ip[:39].strip()
    if not checker.is_ip_address(args.ip):
        logging.info(f"{args.ip} is not a valid IP address.")
        sys.exit(1)

    checker.download_files(force=args.force_download)
    checker.load_data()
    results = checker.lookup_ip(args.ip)

    if not results:
        print(f"No matches found for IP {args.ip}")
    else:
        print(f"Matches for IP {args.ip}:")
        for res in results:
            print("Match:")
            for key, value in res.items():
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                print(f"  {key}: {value}")
            print("")


if __name__ == "__main__":
    main()
