import psutil
from scapy.all import ARP, Ether, srp, conf, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
import ipaddress
import socket
import logging

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
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == ip:
                        for addr in addrs:
                            if addr.family == psutil.AF_LINK:
                                return addr.address
    except ValueError:
        logging.error(f"Invalid IP address: {ip}")
    return None

def scan_network(ip_range, discovered_devices):
    """
    Scan the local network for devices.
    """
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for _, received in answered_list:
        device = (received.psrc, received.hwsrc)
        if device not in discovered_devices:
            discovered_devices.add(device)
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            logging.info(f"Discovered device - IP: {received.psrc}, MAC: {received.hwsrc}")

    return devices

def fetch_network_connections():
    """
    Fetch network connections.
    """
    return psutil.net_connections(kind='inet')