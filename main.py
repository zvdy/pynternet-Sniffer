import psutil
from scapy.all import ARP, Ether, srp, conf, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
import time
import logging
import sys
import select
import ipaddress
import argparse
import socket
from datetime import datetime

# Generate a timestamped log file name
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f'network_activity_{timestamp}.log'

logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s - %(message)s')

def is_valid_ip(ip):
    """
    Validate the given IP address.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_ip_mac_creator(ip):
    """
    Get the MAC address and creator of a given IP using ARP for IPv4 and ICMPv6 for IPv6.
    """
    if not is_valid_ip(ip):
        logging.error(f"Invalid IP address: {ip}")
        return []

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            # Create an ARP request packet
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Send the packet and get the response
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

            devices = []
            for _, received in answered_list:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})

            return devices
        elif ip_obj.version == 6:
            # Create an ICMPv6 Neighbor Solicitation packet
            ns = IPv6(dst=ip)/ICMPv6ND_NS(tgt=ip)/ICMPv6NDOptSrcLLAddr(lladdr=conf.iface.mac)
            answered_list = srp(ns, timeout=1, verbose=False)[0]

            devices = []
            for _, received in answered_list:
                devices.append({'ip': received[IPv6].src, 'mac': received[ICMPv6NDOptSrcLLAddr].lladdr})

            return devices
    except PermissionError as e:
        logging.error(f"PermissionError: {e}")
        return []
    except Exception as e:
        logging.error(f"Error: {e}")
        return []

def get_local_mac(ip):
    """
    Get the MAC address of the local machine for the given IP.
    """
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == ip:
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        return addr.address
    return None

def monitor_network_activity(log_file, log_to_terminal):
    """
    Monitor network activity and log it to a file and optionally to the terminal.
    """
    permission_error_count = 0
    max_permission_errors = 5

    with open(log_file, 'a') as f:
        while True:
            try:
                logging.debug("Fetching network connections...")
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        local_ip = conn.laddr.ip
                        local_mac = get_local_mac(local_ip)
                        remote_ip = conn.raddr.ip if conn.raddr else 'N/A'
                        remote_port = conn.raddr.port if conn.raddr else 'N/A'
                        logging.debug(f"Established connection found: Local IP: {local_ip}, Local MAC: {local_mac}, Remote IP: {remote_ip}, Remote Port: {remote_port}")
                        devices = get_ip_mac_creator(remote_ip)
                        for device in devices:
                            log_entry = f"Local IP: {local_ip}, Local MAC: {local_mac}, Remote IP: {remote_ip}, Remote Port: {remote_port}, Remote MAC: {device['mac']}\n"
                            f.write(log_entry)
                            if log_to_terminal:
                                print(log_entry.strip())
                            logging.debug(f"Logged entry: {log_entry.strip()}")
                time.sleep(5)  # Adjust the sleep time as needed

                # Check for exit signal
                if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    key = sys.stdin.read(1)
                    if key == 'q' or key == '\x1b':  # 'q' or 'Esc'
                        logging.info("Exiting...")
                        break

                permission_error_count = 0  # Reset the count if no error occurs

            except PermissionError as e:
                logging.error(f"PermissionError: {e}")
                permission_error_count += 1
                if permission_error_count >= max_permission_errors:
                    logging.error("Too many PermissionErrors. Exiting...")
                    break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor network activity and log it.")
    parser.add_argument('-t', '--terminal', action='store_true', help="Log activity to the terminal as well as to the file")
    args = parser.parse_args()

    print("Press 'q' or 'Esc' to exit.")
    logging.info("Starting network activity monitoring...")
    monitor_network_activity(log_file, args.terminal)