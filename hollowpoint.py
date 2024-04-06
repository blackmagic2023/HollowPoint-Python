import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import requests

# IP address blocks for major regions with subnet masks
REGION_IP_BLOCKS = {
    "North America": [("8.0.0.0", "255.0.0.0"), ("12.0.0.0", "255.0.0.0"), ("24.0.0.0", "255.0.0.0"), ("32.0.0.0", "255.0.0.0"), ("40.0.0.0", "255.0.0.0")],
    "Europe": [("5.0.0.0", "255.0.0.0"), ("46.0.0.0", "255.0.0.0"), ("77.0.0.0", "255.0.0.0"), ("78.0.0.0", "255.0.0.0"), ("79.0.0.0", "255.0.0.0")],
    "Asia": [("1.0.0.0", "255.0.0.0"), ("14.0.0.0", "255.0.0.0"), ("27.0.0.0", "255.0.0.0"), ("36.0.0.0", "255.0.0.0"), ("49.0.0.0", "255.0.0.0")],
    "Africa": [("41.0.0.0", "255.0.0.0"), ("102.0.0.0", "255.0.0.0"), ("105.0.0.0", "255.0.0.0"), ("154.0.0.0", "255.0.0.0"), ("196.0.0.0", "255.0.0.0")],
    "South America": [("177.0.0.0", "255.0.0.0"), ("179.0.0.0", "255.0.0.0"), ("181.0.0.0", "255.0.0.0"), ("186.0.0.0", "255.0.0.0"), ("190.0.0.0", "255.0.0.0")],
    "Oceania": [("1.0.0.0", "255.0.0.0"), ("14.0.0.0", "255.0.0.0"), ("27.0.0.0", "255.0.0.0"), ("36.0.0.0", "255.0.0.0"), ("49.0.0.0", "255.0.0.0")],
}

# Commonly used ports for scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Function to generate a random IPv4 address within a specific IP address block using subnet mask
def generate_random_ip(region):
    ip_blocks = REGION_IP_BLOCKS.get(region)
    if not ip_blocks:
        print("Invalid region selected. Using global IP address blocks.")
        ip_blocks = REGION_IP_BLOCKS.get("Global")
    
    network_address, subnet_mask = random.choice(ip_blocks)
    network_int = struct.unpack("!I", socket.inet_aton(network_address))[0]
    subnet_mask_int = struct.unpack("!I", socket.inet_aton(subnet_mask))[0]
    
    # Calculate the maximum number of hosts in the subnet
    max_hosts = 2 ** (32 - bin(subnet_mask_int).count('1')) - 2
    
    # Generate a random host address within the subnet
    host_int = random.randint(1, max_hosts)
    
    # Combine the network address and host address to get the IP
    ip_int = network_int | host_int
    return socket.inet_ntoa(struct.pack("!I", ip_int))

# Function to ping an IP address
def ping_ip(ip):
    try:
        subprocess.check_output(['ping', '-c', '1', ip], stderr=subprocess.STDOUT, timeout=0.5)
        return ip
    except subprocess.CalledProcessError:
        return None
    except subprocess.TimeoutExpired:
        return None

# Function to save online IP addresses with open ports to a file
def save_to_file(online_ips):
    with open('targets.txt', 'w') as f:
        for ip, ports, city, region, country in online_ips:
            f.write(f"IP: {ip}, Open Ports: {ports}, Location: {city}, {region}, {country}\n")

# Function to get geolocation information for an IP address
def get_geolocation(ip):
    response = requests.get(f"http://ipinfo.io/{ip}/json")
    if response.status_code == 200:
        data = response.json()
        return data.get("city"), data.get("region"), data.get("country")
    return None, None, None

# Function to scan common ports on an IP address
def scan_ports(ip):
    open_ports = []
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)  # Set timeout for connection attempt
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            pass  # Ignore any errors and continue scanning other ports
    return open_ports

# Function to display usage instructions
def display_usage():
    print("Usage: python ip_scanner.py <num_ips> [<region>]")
    print("Arguments:")
    print("  <num_ips>: Number of IP addresses to generate (default: 10)")
    print("  <region>: Optional. Region to generate IP addresses for. Available regions:")
    for region in REGION_IP_BLOCKS:
        print(f"    - {region}")

# Main function
def main(num_ips, region=None):
    print("Starting IP scanning...")
    if region and region not in REGION_IP_BLOCKS:
        print("Invalid region. Run the script with -h or --help for usage instructions.")
        return

    online_ips_with_ports = []

    def scan_ip(ip):
        if ping_ip(ip):
            print(f"Scanning IP: {ip}")
            open_ports = scan_ports(ip)
            if open_ports:
                city, region, country = get_geolocation(ip)
                online_ips_with_ports.append((ip, open_ports, city, region, country))

    threads = []
    for _ in range(10):  # Number of threads to use
        t = threading.Thread(target=lambda: [scan_ip(generate_random_ip(region)) for _ in range(num_ips)])
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if online_ips_with_ports:
        print("Online IP addresses with open ports:")
        for ip, ports, city, region, country in online_ips_with_ports:
            print(f"IP: {ip}, Open Ports: {ports}, Location: {city}, {region}, {country}")
        save_to_file(online_ips_with_ports)  # Save the results to a file
        print("Results saved to targets.txt")
    else:
        print("No online IP addresses with open ports found")

    print("IP scanning completed.")

if __name__ == "__main__":
    if len(sys.argv) == 1 or sys.argv[1] in {"-h", "--help"}:
        display_usage()
    else:
        num_ips = int(sys.argv[1]) if len(sys.argv) > 1 else 10  # Number of IP addresses to generate (default: 10)
        region = sys.argv[2] if len(sys.argv) > 2 else None  # Region to generate IP addresses for
        main(num_ips, region)
