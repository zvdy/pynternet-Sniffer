"""
MAC manufacturer lookup module.
"""

import re
from mac_vendor_lookup import MacLookup

# Initialize the MacLookup instance
mac_lookup = MacLookup()

def add_mac_manufacturer(log_entries):
    """
    Add MAC manufacturer information to log entries.
    
    Args:
        log_entries (list of str): List of log entries.
    
    Returns:
        list of str: Updated log entries with MAC manufacturer information.
    """
    # Regex to match MAC addresses
    mac_regex = re.compile(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})')

    # Process each log entry
    updated_log_entries = []
    for entry in log_entries:
        mac_addresses = mac_regex.findall(entry)
        for mac in mac_addresses:
            mac_str = ''.join(mac)
            try:
                manufacturer = mac_lookup.lookup(mac_str)
            except Exception:
                manufacturer = 'Unknown'
            entry = entry.replace(mac_str, f'{mac_str} ({manufacturer})')
        updated_log_entries.append(entry)

    return updated_log_entries