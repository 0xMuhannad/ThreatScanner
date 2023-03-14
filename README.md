# ThreatScanner

ThreatScanner is an efficient multi-threading script that utilizes the AbuseIPDB and VirusTotal APIs to retrieve crucial information from a vast number of IP addresses. the script will quickly generate an excel file with a table of the IP addresses and their corresponding information from both websites.

Security analysts regularly review and analyze a large number of IP addresses to identify potential security threats. It is crucial for them to identify the level of maliciousness, the geographic location, domain name, and other relevant information associated with the IP addresses. By having this information readily available, analysts can expedite the analysis process and identify potential threats more efficiently.

# Installation

ThreatScanner requires the usage of python3. Furthermore, there are libraries are required to be installed prior using the script. 
```bash
python3 -m pip install -r requirements.txt
```
# Requirement

ThreatScanner needs at least a valid API key for either AbuseIPDB or VirusTotal to run successfully. The API keys has to be within a text file and follows the format found api keys.txt file. Each Website and API in a separate line. 

```
VirusTotal api_key 
AbuseIPDB api_key
```
# Usage
The script offers multiple options, which can be viewed by supplying the '-h' flag to see the available options.
 * -f: The path to the input file containing IP addresses.
 * -api: API keys text file with the same format of api keys.txt.
 * -l: a path to save the generated excel file. [optional]
 * -a: Use AbuseIPDB only to scan IP addresses. [optional]
 * -v: Use VirusTotal only to scan IP addresses.[optional]
 
```
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
   ██║   ███████║██████╔╝█████╗  ███████║   ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

Author: Muhannad Alruwais
Email: Muhannadbr1@gmail.com
Twitter: MuhannadRu
Version: 1.0  

usage: python3 ThreatScanner.py [-f] IP_File -api API_Key_File | optional -l -a -v  

Accepts: -f or --file for csv, xlsx or txt files only. Additionally, accepts a text file containing API keys.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The path to the input file containing IP addresses. 
  -l LOCATION, --location LOCATION
                        Location to save the generated excel file. By default it will be created at the same directory
  -a, --AbuseIPDB       Use AbuseIPDB only to scan IP addresses. If neither -a nor -v is specified, both AbuseIPDB and VirusTotal will be used.
  -v, --VirusTotal      Use VirusTotal only to scan IP addresses. If neither -a nor -v is specified, both AbuseIPDB and VirusTotal will be used.
  -api API, --api API   Path to API key text file.

IP requirement:
  The list of IP addresses can be provided as:
    - A single IP address (e.g., 8.8.8.8)
    - Multiple IP addresses separated by space (e.g., 8.8.8.8 8.8.4.4)
    - Sanitized IP address (e.g., 8[.]8[.]8[.]8)
```
# Demo

The script is relatively easy to use, and below is an example of how to use it.
 * The script has generated an excel file and its not shown in the below GIF. 

![Alt Text](https://github.com/0xMuhannad/ThreatScanner/blob/main/ThreatScanner.gif)
