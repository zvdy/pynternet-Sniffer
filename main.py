"""
Main module for network activity monitoring.
"""

import sys
import select
import time
import argparse
import logging
from network_scanner import scan_network, get_local_mac, fetch_network_connections
from mac_manufacturer import add_mac_manufacturer
from logger import setup_logging

def monitor_network_activity(log_to_terminal, mac_address_only, ip_range):
    """
    Monitor network activity and log it to a file and optionally to the terminal.
    """
    permission_error_count = 0
    max_permission_errors = 5
    logged_local_macs = set()
    discovered_devices = set()

    logging.info("Scanning the local network for devices...")  # Print this message only once
    logging.debug("Fetching network connections...")  # Print this message only once

    while True:
        try:
            connections = fetch_network_connections()
            log_entries = []
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    local_ip = conn.laddr.ip
                    local_mac = get_local_mac(local_ip)
                    if mac_address_only and local_mac in logged_local_macs:
                        continue
                    logged_local_macs.add(local_mac)
                    remote_ip = conn.raddr.ip if conn.raddr else 'N/A'
                    remote_port = conn.raddr.port if conn.raddr else 'N/A'
                    log_entry = (
                        f"Local IP: {local_ip}, Local MAC: {local_mac}, "
                        f"Remote IP: {remote_ip}, Remote Port: {remote_port}"
                    )
                    log_entries.append(log_entry)
                    logging.info(log_entry)
                    if log_to_terminal:
                        print(log_entry)
            
            # Scan the network for devices
            scan_network(ip_range, discovered_devices)

            # Add MAC manufacturer information to log entries
            updated_log_entries = add_mac_manufacturer(log_entries)
            for entry in updated_log_entries:
                logging.info(entry)
                if log_to_terminal:
                    print(entry)

            time.sleep(5)  # Adjust the sleep time as needed

            # Check for exit signal
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                key = sys.stdin.read(1)
                if key in {'q', '\x1b'}:  # 'q' or 'Esc'
                    logging.info("Exiting...")
                    break

            permission_error_count = 0  # Reset the count if no error occurs

        except PermissionError as e:
            logging.error("PermissionError: %s", e)
            permission_error_count += 1
            if permission_error_count >= max_permission_errors:
                logging.error("Too many PermissionErrors. Exiting...")
                break
        except Exception as e:
            logging.error("Error: %s", e)
            break
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor network activity and log it.")
    parser.add_argument('-t', '--terminal', action='store_true', help="Log activity to the terminal as well as to the file")
    parser.add_argument('-m', '--mac-address-only', action='store_true', help="Log only the first request of each MAC address")
    parser.add_argument('-r', '--range', type=str, default="192.168.1.1/24", help="IP range to scan for devices")
    args = parser.parse_args()

    setup_logging(args.terminal)

    print("Press 'q' or 'Esc' to exit.")
    logging.info("Starting network activity monitoring...")
    monitor_network_activity(args.terminal, args.mac_address_only, args.range)