# HollowPoint

HollowPoint is a Python tool for generating random IP addresses within specific regions, pinging those IP addresses, scanning common ports, and detecting the operating system. It's designed for network enthusiasts who want to explore and analyze network configurations and behaviors.
Features

   - Generate Random IPs: Generates random IP addresses within specific regions.
   - Ping IPs: Checks if the IP addresses are online.
   - Port Scanning: Scans common ports on the IP addresses.
   - OS Detection: Detects the operating system using nmap.
   - Geolocation: Fetches geolocation information for the IP addresses.

## Installation

Ensure you have Python installed. Additionally, you need the following libraries and tools:

   - requests
   - nmap (install via your package manager)
   - proxychains (optional, if you want to use it for OS detection)

You can install the required Python libraries using pip:

```sh
pip install requests
```

## Usage

Run the script with the number of IP addresses you want to generate and optionally the region:

```sh
python hollowpoint.py <num_ips> [<region>]
```

## Arguments
```
    <num_ips>: Number of IP addresses to generate (default: 10)
    <region>: Optional. Region to generate IP addresses for. Available regions:
        North America
        Europe
        Asia
        Africa
        South America
        Oceania
        Random: Generate IP addresses in a random region
```

## Example

```sh
python hollowpoint.py 10 "North America"
```

## How It Works

   - Generate Random IPs: Generates IP addresses within specified regions.
   - Ping IPs: Checks if the generated IPs are online.
   - Port Scanning: Scans common ports on online IPs.
   - Geolocation: Retrieves geolocation data for online IPs.
   - OS Detection: Uses nmap to detect the operating system of online IPs with open ports.

## Example Output

```sh
IP: 192.168.1.1, Open Ports: [80, 443], Location: New York, NY, USA
OS detection for IP 192.168.1.1:
Linux 2.6.X
```

## Disclaimer

This tool is for educational purposes only. Always ensure you have permission before scanning or probing any network or IP address. Unauthorized network scanning is illegal and unethical.
