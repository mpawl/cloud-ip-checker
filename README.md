# cloud_ip_checker

`cloud_ip_checker.py` will take in an IP address and look up against cloud provider published information on IP address blocks. 

`cloud_ip_checker.py` queries against the following providers:

* Amazon Web Services (AWS)
* Google Services
* Google Cloud Platform (GCP)
* Microsoft Azure 
* Microsoft 365 (M365)
* Oracle Cloud Infrastructure (OCI)
* Digital Ocean
* Linode
* Cloudflare
* Fastly

# Dependencies

This tool does not have any external dependencies. Only Python 3.6+. 

# Installation

`cloud_ip_checker.py` requires a directory in the present working directory to store the cloud provider data files. By default, this directory is `./cloud_ip_data`. There is an empty directory in this repository. Changing the data directory requires modification of the `DATA_DIR` variable in `cloud_ip_checker.py`. 

Current data files for AWS, GCP, and OCI can be fetched programmatically by the script. Microsoft does not published an automation friendly endpoint. `cloud_ip_checker.py` embeds a URL for one version of M365 and Azure data files from June 2025. Use caution when using `--force-download` command line option. It could overwrite your newer, manually loaded Microsoft data files. 

## Loading Microsoft Data Files

Below are instructions to manually load Microsoft data files. 

* Updated Azure data files can be found [here](https://www.microsoft.com/en-us/download/details.aspx?id=56519). 
	* Use the Download button to download manually and place the file in `DATA_DIR\azure.json` OR
	* Copy the link in the Download button and execute: `curl -sSL -o ./cloud_ip_data/azure.json "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20250929.json"`
* Updated M365 data files can be found [here](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide). 
	* Use the JSON formatted link under the Download section to download manually and place the file in `DATA_DIR\m365.json` OR
	* Copy the link in Download > JSON formatted link and execute: `curl -sSL -o ./cloud_ip_data/azure.json "hhttps://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"`

# Usage

Below is the help screen for `cloud_ip_checker.py`, detailing the command line options. 

```
usage: cloud_ip_checker.py [-h] --ip IP [--force-download]

Lookup cloud provider info for an IP address.

options:
  -h, --help        show this help message and exit
  --ip IP           IP address to check
  --force-download  Force re-download of cloud IP data
```

# Output

`cloud_ip_checker.py` will output to STDOUT or return an object programmatically. 

## STDOUT

Running `cloud_ip_checker.py` from the command line will output data found in the cloud data files for the IP provided. Data fields vary based on the data the provider publishes. Each data file is checked. an IP could be found in multiple data files (this is common for M365). Some examples are below. 

### AWS

```
Match:
  provider: AWS
  cidr: 18.189.0.0/16
  ip_prefix: 18.189.0.0/16
  region: us-east-2
  service: AMAZON
  network_border_group: us-east-2

Match:
  provider: AWS
  cidr: 18.189.0.0/16
  ip_prefix: 18.189.0.0/16
  region: us-east-2
  service: EC2
  network_border_group: us-east-2
```

### Azure

```
Match:
  provider: Azure
  cidr: 4.145.74.52/30
  service: ActionGroup
  changeNumber: 48
  region:
  regionId: 0
  platform: Azure
  systemService: ActionGroup
  networkFeatures: API, NSG, UDR, FW

Match:
  provider: Azure
  cidr: 4.145.74.52/30
  service: ActionGroup.SoutheastAsia
  changeNumber: 5
  region: southeastasia
  regionId: 2
  platform: Azure
  systemService: ActionGroup
  networkFeatures: None

Match:
  provider: Azure
  cidr: 4.145.0.0/16
  service: AzureCloud.southeastasia
  changeNumber: 93
  region: southeastasia
  regionId: 2
  platform: Azure
  systemService:
  networkFeatures: API, NSG

Match:
  provider: Azure
  cidr: 4.145.0.0/16
  service: AzureCloud
  changeNumber: 260
  region:
  regionId: 0
  platform: Azure
  systemService:
  networkFeatures: API, NSG
```

### Google

```
Match:
  provider: Google
  cidr: 8.8.4.0/24
  ipv4Prefix: 8.8.4.0/24
```

### Oracle

```
Matches for IP 150.136.138.1:
Match:
  provider: OCI
  region: us-ashburn-1
  cidr: 150.136.0.0/16
  tags: OCI
```

### M365

```
Matches for IP 2620:1ec:4::152:
Match:
  provider: Azure
  cidr: 2620:1ec:4::/46
  service: AzureFrontDoor.FirstParty
  changeNumber: 20
  region:
  regionId: 0
  platform: Azure
  systemService: AzureFrontDoor
  networkFeatures: API, NSG, UDR, FW

Match:
  provider: M365
  cidr: 2620:1ec:4::152/128
  serviceArea: Exchange
  serviceAreaDisplayName: Exchange Online
  id: 1
  urls: outlook.cloud.microsoft, outlook.office.com, outlook.office365.com
  tcpPorts: 80,443
  udpPorts: 443
  expressRoute: True
  category: Optimize

Match:
  provider: M365
  cidr: 2620:1ec:4::152/128
  serviceArea: Exchange
  serviceAreaDisplayName: Exchange Online
  id: 2
  urls: outlook.office365.com, smtp.office365.com
  tcpPorts: 143, 587, 993, 995
  expressRoute: True
  category: Allow
  notes: POP3, IMAP4, SMTP Client traffic
```

### Digital Ocean

```
Matches for IP 45.55.1.1:
Match:
  provider: Digital Ocean
  cidr: 45.55.0.0/19
  country: US
  region: US-CA
  city: San Francisco
  postal_code: 94124
```

### Linode

```
Matches for IP 66.228.32.0:
Match:
  provider: Linode
  cidr: 66.228.32.0/24
  country: US
  region: US-NJ
  city: Cedar Knolls
```

### Cloudflare

```
Matches for IP 103.21.244.5:
Match:
  provider: Cloudflare
  cidr: 103.21.244.0/22
```
### Fastly

```
Matches for IP 23.235.32.1:
Match:
  provider: Fastly
  cidr: 23.235.32.0/20
```

## Programmatically

If interacting programmatically, a List of Dictionaries will be returned if one or more matches are found.
