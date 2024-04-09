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
COMMON_PORTS = [20, 21, 22, 23, 25, 53, 69, 80, 110, 135, 137, 139, 143, 443, 445, 993, 995, 1433, 1434, 1723, 3306, 3389, 4444, 5900, 8080, 8443]

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

# Function to generate a random IP address block
def generate_random_block():
    region = random.choice(list(REGION_IP_BLOCKS.keys()))
    return region, generate_random_ip(region)

# Function to ping an IP address
def ping_ip(ip):
    try:
        subprocess.check_output(['ping', '-c', '1', ip], stderr=subprocess.STDOUT)
        return ip
    except subprocess.CalledProcessError:
        return None
    except subprocess.TimeoutExpired:
        return None

# Function to save online IP addresses to a file
def save_to_file(online_ips):
    mode = 'a' if os.path.exists('online_ips.txt') else 'w'
    with open('online_ips.txt', mode) as f:
        for ip in online_ips:
            f.write(ip + '\n')

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

# Function to detect OS using nmap through proxychains with a slight delay
def detect_os(ip):
    try:
        output = subprocess.check_output(['nmap', '-O', '-A', '-Pn', ip], timeout=60)
        return output.decode("utf-8")
    except subprocess.TimeoutExpired:
        print(f"Timeout occurred while detecting OS for IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while detecting OS for IP: {ip}, Error: {e}")
    finally:
        time.sleep(1)  # Add a 1-second delay after each OS detection attempt
    return None

# Function to display usage instructions
def display_usage():
    print("Usage: python ip_scanner.py <num_ips> [<region>]")
    print("Arguments:")
    print("  <num_ips>: Number of IP addresses to generate (default: 10)")
    print("  <region>: Optional. Region to generate IP addresses for. Available regions:")
    for region in REGION_IP_BLOCKS:
        print(f"    - {region}")
    print("    - Random: Generate IP addresses in a random region")

# Main function
def main(num_ips, region=None):
    if region == "Random":
        region, ip = generate_random_block()
        print(f"Random region selected: {region}")
    elif region and region not in REGION_IP_BLOCKS:
        print("Invalid region. Run the script with -h or --help for usage instructions.")
        return

    online_ips_with_ports = []

    def scan_ip(ip):
        if ping_ip(ip):
            open_ports = scan_ports(ip)
            if open_ports:
                city, region, country = get_geolocation(ip)
                online_ips_with_ports.append((ip, open_ports, city, region, country))
                print(f"IP: {ip}, Open Ports: {open_ports}, Location: {city}, {region}, {country}")

                # Update OS detection
                os_info = detect_os(ip)
                if os_info:
                    print(f"OS detection for IP {ip}:")
                    print(os_info)
            else:
                print(f"IP: {ip}, No open ports found")
        else:
            print(f"IP: {ip}, Offline")

    num_threads = min(num_ips, 100)  # Limit the number of threads to avoid excessive resource usage
    threads = []

    for _ in range(num_threads):
        t = threading.Thread(target=lambda: [scan_ip(generate_random_ip(region)) for _ in range(num_ips // num_threads)])
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # Save online IPs with open ports to a file
    if online_ips_with_ports:
        save_to_file([f"IP: {ip}, Open Ports: {ports}, Location: {city}, {region}, {country}" for ip, ports, city, region, country in online_ips_with_ports])
    else:
        print("No online IPs with open ports found.")

if __name__ == "__main__":
    num_ips = 10
    region = None

    if len(sys.argv) >= 2:
        if sys.argv[1] in ('-h', '--help'):
            display_usage()
            sys.exit(0)
        try:
            num_ips = int(sys.argv[1])
            if len(sys.argv) >= 3:
                region = sys.argv[2]
        except ValueError:
            print("Invalid number of IP addresses. Please provide a valid integer.")
            sys.exit(1)

    main(num_ips, region)
