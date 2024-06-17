from scapy.all import *
from netaddr import IPNetwork
from scapy.layers.inet import TCP


def discover_active_hosts(network_prefix):
    # Create IP range from network prefix (e.g., '192.168.1.0/24')
    ip_range = IPNetwork(network_prefix)

    active_hosts = []
    for ip in ip_range:
        if ip == ip_range.network or ip == ip_range.broadcast:
            continue  # Skip network address and broadcast address
        response = sr1(IP(dst=str(ip)) / ICMP(), timeout=2, verbose=0)
        if response:
            active_hosts.append(str(ip))
    return active_hosts


def scan_ports(target_ip, ports, timeout=1):
    open_ports = []
    for port in ports:
        response = sr1(IP(dst=target_ip) / TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            open_ports.append(port)
    return open_ports


if __name__ == "__main__":
    network_prefix = "192.168.100.1/24"  # Replace with your network prefix
    active_hosts = discover_active_hosts(network_prefix)

    print("Active Hosts:")
    print(active_hosts)

    ports_to_scan = range(1, 100)  # Example: Scan ports 1 to 99
    for host in active_hosts:
        open_ports = scan_ports(host, ports_to_scan)
        if open_ports:
            print(f"Open ports on {host}: {open_ports}")
        else:
            print(f"No open ports on {host}")
