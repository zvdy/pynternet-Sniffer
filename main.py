import psutil
from scapy.all import ARP, Ether, srp
import time
import logging
import sys
import select
import ipaddress

logging.basicConfig(filename='network_activity.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')

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
    Get the MAC address and creator of a given IP using ARP.
    """
    if not is_valid_ip(ip):
        logging.error(f"Invalid IP address: {ip}")
        return []

    try:
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
    except PermissionError as e:
        logging.error(f"PermissionError: {e}")
        return []

def monitor_network_activity(log_file):
    """
    Monitor network activity and log it to a file.
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
                        remote_ip = conn.raddr.ip if conn.raddr else 'N/A'
                        remote_port = conn.raddr.port if conn.raddr else 'N/A'
                        logging.debug(f"Established connection found: Local IP: {local_ip}, Remote IP: {remote_ip}, Remote Port: {remote_port}")
                        devices = get_ip_mac_creator(remote_ip)
                        for device in devices:
                            log_entry = f"Local IP: {local_ip}, Remote IP: {remote_ip}, Remote Port: {remote_port}, MAC: {device['mac']}\n"
                            f.write(log_entry)
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
    log_file = "network_activity.log"
    print("Press 'q' or 'Esc' to exit.")
    logging.info("Starting network activity monitoring...")
    monitor_network_activity(log_file)