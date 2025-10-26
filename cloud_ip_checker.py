#!/usr/bin/env python3
"""Cloud IP Checker - Lookup cloud provider info for IP addresses."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import os
import shutil
import socket
import sys
import time
import urllib.request
from typing import Any, Dict, List, Optional, Set, TypedDict
from urllib.error import HTTPError, URLError

# This is the directory inside of the current directory where data files will be stored.
DATA_DIR = "cloud_ip_data"

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_FACTOR = 1.5
DEFAULT_RETRY_DELAY = 0.5
DEFAULT_USER_AGENT = "cloud-ip-checker/1.0"
DEFAULT_LOG_FORMAT = "%(levelname)s: %(message)s"

__version__ = "1.0.0"

__all__ = [
    "CloudIPChecker",
    "CloudIPCheckerError",
    "DownloadError",
    "ParseError",
    "LookupError",
    "__version__",
]


class ProviderMetaRequired(TypedDict):
    """Required fields for provider metadata."""
    filename: str


class ProviderMeta(ProviderMetaRequired, total=False):
    """Provider metadata structure."""
    url: str
    urls: List[str]

# Monitored providers and the URLs to download the data files. Microsoft data files are not currently
# automatable. Reference links are included, however following instructions in README is preferred.
PROVIDERS = {
    "azure": {
        "url": "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20251020.json",
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


class CloudIPCheckerError(Exception):
    """Base exception for CloudIPChecker errors."""
    pass


class DownloadError(CloudIPCheckerError):
    """Raised when provider data cannot be downloaded."""
    pass


class ParseError(CloudIPCheckerError):
    """Raised when provider data cannot be parsed."""
    pass


class LookupError(CloudIPCheckerError):
    """Raised when IP lookup fails."""
    pass


class CloudIPChecker:
    """Cloud IP address checker for multiple cloud providers."""
    
    def __init__(
        self,
        data_dir: str = DATA_DIR,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        retry_delay: float = DEFAULT_RETRY_DELAY,
        user_agent: str = DEFAULT_USER_AGENT,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize CloudIPChecker.
        
        Args:
            data_dir: Directory where provider data files are stored
            timeout: HTTP request timeout in seconds
            max_retries: Maximum retry attempts for failed downloads
            backoff_factor: Multiplier for retry delay (exponential backoff)
            retry_delay: Initial delay between retries in seconds
            user_agent: User-Agent header for HTTP requests
            logger: Optional logger instance (creates default if None)
        """
        self.data_dir = data_dir
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.retry_delay = retry_delay
        self.user_agent = user_agent
        self.logger = logger or logging.getLogger(__name__)
        self.providers_data: Dict[str, Any] = {}
        self._network_cache: Dict[str, ipaddress._BaseNetwork] = {}
        self._invalid_cidrs: Set[str] = set()

    def download_files(self, force: bool = False):
        """Download provider data files with retry logic."""
        os.makedirs(self.data_dir, exist_ok=True)
        for provider, meta in PROVIDERS.items():
            filename = meta.get("filename")
            if not filename:
                self.logger.error("Provider %s missing filename", provider)
                continue
                
            path = os.path.join(self.data_dir, filename)
            urls = meta.get("urls")
            single_url = meta.get("url")

            if urls:
                if not force and os.path.exists(path):
                    self.logger.info("%s data already present.", provider)
                    continue
                try:
                    self._download_multiple_urls(provider, urls, path)
                except DownloadError as exc:
                    self.logger.error("%s", exc)
                    if os.path.exists(path):
                        os.remove(path)
                continue

            if single_url is None:
                self.logger.debug("%s data handled manually.", provider)
                continue

            if force or not os.path.exists(path):
                try:
                    self._download_single_url(provider, single_url, path)
                except DownloadError as exc:
                    self.logger.error("%s", exc)
                    if os.path.exists(path):
                        os.remove(path)
            else:
                self.logger.info("%s data already present.", provider)

    def _download_multiple_urls(self, provider: str, urls: List[str], path: str) -> None:
        """Download and merge data from multiple URLs."""
        cidr_lines: List[str] = []
        for index, url in enumerate(urls, start=1):
            self.logger.info("Downloading %s data (%s/%s)...", provider, index, len(urls))
            raw_data = self._fetch_url(provider, url)
            try:
                text = raw_data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DownloadError(f"Failed to decode {provider} data from {url}: {exc}") from exc
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            cidr_lines.extend(lines)

        with open(path, "w", newline="\n") as out_file:
            out_file.write("\n".join(cidr_lines) + ("\n" if cidr_lines else ""))

    def _download_single_url(self, provider: str, url: str, path: str) -> None:
        """Download data from a single URL."""
        self.logger.info("Downloading %s data...", provider)
        raw_data = self._fetch_url(provider, url)
        with open(path, "wb") as out_file:
            out_file.write(raw_data)

    def _fetch_url(self, provider: str, url: str) -> bytes:
        """Fetch URL with retry logic and exponential backoff."""
        last_error: Optional[BaseException] = None
        delay = self.retry_delay

        for attempt in range(self.max_retries + 1):
            try:
                request = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return response.read()
            except (HTTPError, URLError, socket.timeout) as exc:
                last_error = exc
                if attempt == self.max_retries:
                    break
                self.logger.warning(
                    "Retrying %s download (%s/%s) after error: %s",
                    provider, attempt + 1, self.max_retries, exc
                )
                time.sleep(delay)
                delay *= self.backoff_factor
            except Exception as exc:
                raise DownloadError(
                    f"Unexpected error downloading {provider} data from {url}: {exc}"
                ) from exc

        raise DownloadError(f"Failed to download {provider} data from {url}: {last_error}")

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
        """Load provider data from files with improved error handling."""
        loaded: Dict[str, Any] = {}
        for provider, meta in PROVIDERS.items():
            filename = meta.get("filename")
            if not filename:
                self.logger.error("Provider %s missing filename", provider)
                continue
                
            path = os.path.join(self.data_dir, filename)
            if not os.path.exists(path):
                self.logger.debug("Skipping %s: file not found at %s", provider, path)
                continue
                
            try:
                if provider == "do":
                    loaded[provider] = self._load_geoip_csv(
                        path,
                        fieldnames=["cidr", "country", "region", "city", "postal_code"]
                    )
                elif provider == "cloudflare":
                    loaded[provider] = self._load_cidr_file(path)
                elif provider == "fastly":
                    with open(path, "r") as f:
                        payload = json.load(f)
                    fastly_records: List[Dict[str, Any]] = []
                    for key in ("addresses", "ipv6_addresses"):
                        for cidr in payload.get(key, []):
                            cidr = cidr.strip()
                            if cidr:
                                fastly_records.append({"cidr": cidr})
                    loaded[provider] = fastly_records
                elif provider == "linode":
                    loaded[provider] = self._load_geoip_csv(
                        path,
                        fieldnames=["ip_prefix", "alpha2code", "region", "city", "postal_code"],
                        rename={
                            "ip_prefix": "cidr",
                            "alpha2code": "country"
                        }
                    )
                else:
                    with open(path, "r") as f:
                        loaded[provider] = json.load(f)
            except FileNotFoundError as exc:
                message = f"File not found for provider {provider}: {path}"
                self.logger.error(message)
                raise ParseError(message) from exc
            except json.JSONDecodeError as exc:
                message = f"Invalid JSON format for provider {provider}: {path}"
                self.logger.error(message)
                raise ParseError(message) from exc
            except csv.Error as exc:
                message = f"Invalid CSV format for provider {provider}: {path}"
                self.logger.error(message)
                raise ParseError(message) from exc
            except OSError as exc:
                message = f"Error reading data for provider {provider}: {path}"
                self.logger.error(message)
                raise ParseError(message) from exc
        
        self.providers_data = loaded
        self._network_cache.clear()
        self._invalid_cidrs.clear()

    def lookup_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Lookup IP address in provider data."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise LookupError(f"{ip} is not a valid IP address.") from exc
        
        if not self.providers_data:
            raise LookupError("Provider data not loaded. Call load_data() first.")
            
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
        """Check if IP is in CIDR range with caching for performance."""
        if cidr in self._invalid_cidrs:
            return False

        network = self._network_cache.get(cidr)
        if network is None:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                self._invalid_cidrs.add(cidr)
                self.logger.warning("Skipping invalid CIDR '%s'", cidr)
                return False
            self._network_cache[cidr] = network
        return ip in network


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point with proper error handling."""
    parser = argparse.ArgumentParser(
        description="Lookup cloud provider info for an IP address."
    )
    parser.add_argument('--ip', required=True, help="IP address to check")
    parser.add_argument(
        '--force-download',
        action='store_true',
        help="Force re-download of cloud IP data"
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds for downloads (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        '--max-retries',
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f"Maximum retry attempts (default: {DEFAULT_MAX_RETRIES})"
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Logging level (default: INFO)"
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}',
        help="Show version and exit"
    )
    args = parser.parse_args(argv)

    # Configure logging
    logging.basicConfig(level=args.log_level, format=DEFAULT_LOG_FORMAT)
    logger = logging.getLogger(__name__)

    # Create checker with configuration
    checker = CloudIPChecker(
        timeout=args.timeout,
        max_retries=args.max_retries,
        logger=logger,
    )

    # Sanitize IP input
    ip_input = args.ip[:39].strip()

    try:
        checker.download_files(force=args.force_download)
        checker.load_data()
        results = checker.lookup_ip(ip_input)
    except LookupError as exc:
        logger.info("%s", exc)
        return 1
    except (DownloadError, ParseError) as exc:
        logger.error("%s", exc)
        return 1
    except CloudIPCheckerError as exc:
        logger.error("%s", exc)
        return 1
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        return 1

    if not results:
        print(f"No matches found for IP {ip_input}")
    else:
        print(f"Matches for IP {ip_input}:")
        for res in results:
            print("Match:")
            for key, value in res.items():
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                print(f"  {key}: {value}")
            print("")

    return 0


if __name__ == "__main__":
    sys.exit(main())
