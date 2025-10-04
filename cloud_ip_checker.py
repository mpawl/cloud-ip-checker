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
from typing import List, Dict, Any, Optional

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
    "linode": {
        "url": "https://geoip.linode.com/",
        "filename": "linode.csv"
    },
    "cloudflare": {
        "urls": [
            "https://www.cloudflare.com/ips-v4/",
            "https://www.cloudflare.com/ips-v6/"
        ],
        "filename": "cloudflare.txt"
    },
    "fastly": {
        "url": "https://api.fastly.com/public-ip-list",
        "filename": "fastly.json"
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
            path = os.path.join(self.data_dir, meta["filename"])
            urls = meta.get("urls")
            single_url = meta.get("url")
            if urls:
                if not force and os.path.exists(path):
                    logging.info(f"{provider} data already present.")
                    continue
                cidr_lines: List[str] = []
                success = True
                for index, url in enumerate(urls):
                    logging.info(f"Downloading {provider} data ({index + 1}/{len(urls)})...")
                    try:
                        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(request) as response:
                            data = response.read().decode("utf-8")
                    except HTTPError as e:
                        logging.error(f"Failed to download {provider} data (HTTP {e.code}: {e.reason}).")
                        success = False
                        break
                    except URLError as e:
                        logging.error(f"Failed to download {provider} data ({e.reason}).")
                        success = False
                        break
                    except Exception as e:
                        logging.error(f"Unexpected error downloading {provider} data: {e}")
                        success = False
                        break
                    lines = [line.strip() for line in data.splitlines() if line.strip()]
                    cidr_lines.extend(lines)
                if not success:
                    if os.path.exists(path):
                        os.remove(path)
                    continue
                try:
                    with open(path, "w", newline="\n") as out_file:
                        if cidr_lines:
                            out_file.write("\n".join(cidr_lines) + "\n")
                        else:
                            out_file.write("")
                except Exception as e:
                    logging.error(f"Unexpected error writing {provider} data: {e}")
                    if os.path.exists(path):
                        os.remove(path)
                    continue
                continue
            if single_url is None:
                continue  # Handled manually
            if force or not os.path.exists(path):
                logging.info(f"Downloading {provider} data...")
                try:
                    request = urllib.request.Request(single_url, headers={"User-Agent": "Mozilla/5.0"})
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

    def _load_geoip_csv(
        self,
        path: str,
        *,
        fieldnames: Optional[List[str]] = None,
        rename: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        rename = rename or {}
        entries: List[Dict[str, Any]] = []
        with open(path, newline="") as raw_file:
            filtered_lines = (
                line
                for line in raw_file
                if line.strip()
                and not line.lstrip().startswith("#")
                and "," in line
            )
            reader = csv.DictReader(
                filtered_lines,
                fieldnames=fieldnames,
                restkey="extra",
                restval=""
            )
            for row in reader:
                normalized: Dict[str, Any] = {}
                for key, value in row.items():
                    if key in (None, "extra"):
                        continue
                    key = key.strip()
                    if not key:
                        continue
                    key = key.lower().replace(" ", "_")
                    key = rename.get(key, key)
                    if key is None:
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
                        normalized[key] = value
                cidr = normalized.get("cidr")
                if not cidr:
                    continue
                entries.append(normalized)
        return entries

    def _load_cidr_file(self, path: str) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        with open(path, "r") as handle:
            for line in handle:
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                entries.append({"cidr": value})
        return entries

    def _collect_geoip_matches(
        self,
        ip_obj: ipaddress._BaseAddress,
        records: List[Dict[str, Any]],
        provider_label: str
    ) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for record in records:
            cidr = record.get("cidr")
            if cidr and self._ip_in_cidr(ip_obj, cidr):
                match = {
                    "provider": provider_label,
                    "cidr": cidr
                }
                for key, value in record.items():
                    if key == "cidr" or not value:
                        continue
                    match[key] = value
                matches.append(match)
        return matches

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
                    self.providers_data[provider] = self._load_geoip_csv(
                        path,
                        fieldnames=["cidr", "country", "region", "city", "postal_code"]
                    )
                elif provider == "cloudflare":
                    self.providers_data[provider] = self._load_cidr_file(path)
                elif provider == "fastly":
                    with open(path, "r") as f:
                        payload = json.load(f)
                    fastly_records: List[Dict[str, Any]] = []
                    for key in ("addresses", "ipv6_addresses"):
                        for cidr in payload.get(key, []):
                            cidr = cidr.strip()
                            if cidr:
                                fastly_records.append({"cidr": cidr})
                    self.providers_data[provider] = fastly_records
                elif provider == "linode":
                    self.providers_data[provider] = self._load_geoip_csv(
                        path,
                        fieldnames=["ip_prefix", "alpha2code", "region", "city", "postal_code"],
                        rename={
                            "ip_prefix": "cidr",
                            "alpha2code": "country"
                        }
                    )
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
                results.extend(self._collect_geoip_matches(ip_obj, data, "Digital Ocean"))

            elif provider == "cloudflare":
                results.extend(self._collect_geoip_matches(ip_obj, data, "Cloudflare"))

            elif provider == "fastly":
                results.extend(self._collect_geoip_matches(ip_obj, data, "Fastly"))

            elif provider == "linode":
                results.extend(self._collect_geoip_matches(ip_obj, data, "Linode"))

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
