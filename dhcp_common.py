# File: dhcp_common.py

import socket
import json
import struct
import uuid
import time
import random
from base64 import b64encode, b64decode

# Standard DHCP message types according to RFC 2131
DHCPDISCOVER = "DHCPDISCOVER"
DHCPOFFER = "DHCPOFFER"
DHCPREQUEST = "DHCPREQUEST"
DHCPACK = "DHCPACK"
DHCPNAK = "DHCPNAK"
DHCPDECLINE = "DHCPDECLINE"
DHCPRELEASE = "DHCPRELEASE"
DHCPINFORM = "DHCPINFORM"

# DHCP options
OPTIONS = {
    "subnet_mask": "255.255.255.0",
    "router": "192.168.1.1",
    "domain_name_server": ["8.8.8.8", "8.8.4.4"],
    "domain_name": "example.local",
    "broadcast_address": "192.168.1.255",
    "ntp_servers": ["192.168.1.1"],
}

def get_mac():
    """Get the MAC address of the current machine in a formatted string."""
    mac = uuid.getnode()
    return ':'.join(f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8))

def generate_xid():
    """Generate a transaction ID for DHCP messages."""
    return random.randint(1, 0xFFFFFFFF)

def create_packet(message_type, mac, xid=None, ciaddr="0.0.0.0", yiaddr="0.0.0.0", 
                 siaddr="0.0.0.0", options=None):
    """Create a DHCP packet with the given parameters."""
    if xid is None:
        xid = generate_xid()
        
    packet = {
        "op": message_type,
        "xid": xid,
        "chaddr": mac,
        "ciaddr": ciaddr,    # Client IP address (filled by client if known)
        "yiaddr": yiaddr,    # 'your' (client) IP address (filled by server)
        "siaddr": siaddr,    # Server IP address
        "timestamp": time.time()
    }
    
    # Add options if provided
    if options:
        packet["options"] = options
        
    return json.dumps(packet).encode()

def create_discover(mac, xid=None):
    """Create a DHCPDISCOVER packet."""
    return create_packet(DHCPDISCOVER, mac, xid)

def create_request(mac, xid, requested_ip, server_id):
    """Create a DHCPREQUEST packet."""
    options = {
        "requested_ip": requested_ip,
        "server_identifier": server_id
    }
    return create_packet(DHCPREQUEST, mac, xid, options=options)

def create_offer(mac, xid, yiaddr, lease_time, server_id):
    """Create a DHCPOFFER packet."""
    options = {
        "subnet_mask": OPTIONS["subnet_mask"],
        "router": OPTIONS["router"],
        "domain_name_server": OPTIONS["domain_name_server"],
        "ip_address_lease_time": lease_time,
        "server_identifier": server_id
    }
    return create_packet(DHCPOFFER, mac, xid, yiaddr=yiaddr, siaddr=server_id, options=options)

def create_ack(mac, xid, yiaddr, lease_time, server_id):
    """Create a DHCPACK packet."""
    options = {
        "subnet_mask": OPTIONS["subnet_mask"],
        "router": OPTIONS["router"],
        "domain_name_server": OPTIONS["domain_name_server"],
        "ip_address_lease_time": lease_time,
        "server_identifier": server_id
    }
    return create_packet(DHCPACK, mac, xid, yiaddr=yiaddr, siaddr=server_id, options=options)

def create_nak(mac, xid, server_id, message="Request declined by server"):
    """Create a DHCPNAK packet."""
    options = {
        "server_identifier": server_id,
        "message": message
    }
    return create_packet(DHCPNAK, mac, xid, siaddr=server_id, options=options)

def create_release(mac, xid, ciaddr, server_id):
    """Create a DHCPRELEASE packet."""
    options = {
        "server_identifier": server_id
    }
    return create_packet(DHCPRELEASE, mac, xid, ciaddr=ciaddr, options=options)

def parse_packet(data):
    """Parse a received packet from JSON to a dictionary."""
    try:
        return json.loads(data.decode())
    except json.JSONDecodeError:
        return {"op": "ERROR", "error": "Invalid packet format"}

def format_lease(seconds: int) -> str:
    """Format lease time in a human-readable format."""
    if seconds >= 86400:  # Days
        days = seconds // 86400
        return f"{days} day{'s' if days != 1 else ''}"
    elif seconds >= 3600:  # Hours
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    elif seconds >= 60:  # Minutes
        mins, secs = divmod(seconds, 60)
        return f"{mins}m {secs}s"
    return f"{seconds}s"