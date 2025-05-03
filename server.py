# File: server.py

import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import time
import random
import json
from dhcp_common import *
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configuration
DEFAULT_LEASE_TIME = 3600  # 1 hour in seconds
MAX_LEASE_TIME = 86400     # 24 hours
MIN_LEASE_TIME = 600       # 10 minutes

# IP pool configuration
NETWORK_PREFIX = "192.168.1"
IP_RANGE_START = 100
IP_RANGE_END = 200
IP_POOL = [f"{NETWORK_PREFIX}.{i}" for i in range(IP_RANGE_START, IP_RANGE_END + 1)]

# Tables for tracking
LEASE_TABLE = {}   # MAC -> lease info mapping
OFFERS = {}        # Temporary storage for offers being processed

# Server identification
SERVER_ID = None  # Will be set to server's actual IP

# Create server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# Get server IP for identification
def get_server_ip():
    try:
        # This creates a socket that doesn't actually connect
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # This triggers the OS to figure out which interface would be used
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"  # Fallback to localhost

SERVER_ID = get_server_ip()

def load_private_key():
    """Load the private key from a file."""
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    """Load the public key from a file."""
    with open("public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())
# Load RSA keys

def choose_ip(mac, requested_ip=None):
    """
    Select an IP to offer to a client.
    Prioritizes:
    1. Previously assigned IP if still available
    2. Specifically requested IP if available
    3. Random available IP from the pool
    """
    # Check if this MAC already has a lease
    if mac in LEASE_TABLE:
        current_ip = LEASE_TABLE[mac]["ip"]
        log_message(f"Client {mac} has existing lease for {current_ip}")
        return current_ip
        
    # Check if the requested IP is valid and available
    if requested_ip and requested_ip in IP_POOL:
        # Make sure it's not leased to someone else
        for m, info in LEASE_TABLE.items():
            if info["ip"] == requested_ip and m != mac:
                log_message(f"Requested IP {requested_ip} is already leased to another client")
                requested_ip = None
                break
                
        if requested_ip:
            log_message(f"Offering requested IP {requested_ip} to {mac}")
            return requested_ip
    
    # Find available IPs
    leased_ips = {info["ip"] for info in LEASE_TABLE.values()}
    offered_ips = {info["ip"] for info in OFFERS.values()}
    unavailable_ips = leased_ips.union(offered_ips)
    
    available_ips = [ip for ip in IP_POOL if ip not in unavailable_ips]
    
    if available_ips:
        # Choose a random IP from available ones
        chosen_ip = random.choice(available_ips)
        log_message(f"Offering available IP {chosen_ip} to {mac}")
        return chosen_ip
    
    log_message(f"ERROR: No IPs available for {mac}")
    return None

def process_discover(packet, client_address):
    """Process a DHCPDISCOVER message."""
    mac = packet["chaddr"]
    xid = packet["xid"]
    
    log_message(f"Received DHCPDISCOVER from {mac} (xid: {xid:08X})")
    
    # Choose an IP to offer
    ip_to_offer = choose_ip(mac)
    
    if ip_to_offer:
        # Create a temporary offer record
        OFFERS[mac] = {
            "ip": ip_to_offer,
            "xid": xid,
            "timestamp": time.time(),
            "client_address": client_address
        }
        
        # Send DHCPOFFER
        offer_packet = create_offer(
            mac, 
            xid, 
            ip_to_offer, 
            DEFAULT_LEASE_TIME,
            SERVER_ID
        )
        
        log_message(f"Sending DHCPOFFER: {ip_to_offer} to {mac} (xid: {xid:08X})")
        server_socket.sendto(offer_packet, client_address)
    else:
        log_message(f"Cannot offer IP to {mac} - pool exhausted")

def process_request(packet, client_address):
    """Process a DHCPREQUEST message."""
    mac = packet["chaddr"]
    xid = packet["xid"]
    options = packet.get("options", {})
    
    # Check if this is a new request or a renewal
    if "requested_ip" in options:
        # New request or rebinding
        requested_ip = options["requested_ip"]
        server_id = options.get("server_identifier")
        
        log_message(f"Received DHCPREQUEST from {mac} for {requested_ip} (xid: {xid:08X})")
        
        # Verify this request is for us or it's a rebinding request
        if server_id and server_id != SERVER_ID:
            # This request is for another DHCP server, ignore it
            log_message(f"Request not for us (server_id: {server_id}), ignoring")
            return
            
        # Check if the IP is still available
        for m, info in LEASE_TABLE.items():
            if info["ip"] == requested_ip and m != mac:
                # IP is already leased to someone else
                log_message(f"Requested IP {requested_ip} is already leased to another client")
                # Send NAK
                nak_packet = create_nak(mac, xid, SERVER_ID, "IP address is already leased")
                server_socket.sendto(nak_packet, client_address)
                return
                
        # Grant the lease
        lease_time = options.get("lease_time", DEFAULT_LEASE_TIME)
        
        # Make sure the lease time is within valid range
        lease_time = min(max(lease_time, MIN_LEASE_TIME), MAX_LEASE_TIME)
        
        LEASE_TABLE[mac] = {
            "ip": requested_ip,
            "lease_time": lease_time,
            "start_time": time.time(),
            "end_time": time.time() + lease_time,
            "xid": xid
        }
        
        # Remove from offers if it was there
        if mac in OFFERS:
            del OFFERS[mac]
        
        # Send ACK
        ack_packet = create_ack(mac, xid, requested_ip, lease_time, SERVER_ID)
        log_message(f"Sending DHCPACK for {requested_ip} to {mac} (lease: {lease_time}s)")
        server_socket.sendto(ack_packet, client_address)
        
        # Update lease table display
        update_lease_table_display()
        
    else:
        # This is a renewal or rebinding
        if mac in LEASE_TABLE:
            current_ip = LEASE_TABLE[mac]["ip"]
            lease_time = options.get("lease_time", DEFAULT_LEASE_TIME)
            
            # Make sure the lease time is within valid range
            lease_time = min(max(lease_time, MIN_LEASE_TIME), MAX_LEASE_TIME)
            
            # Update the lease
            LEASE_TABLE[mac] = {
                "ip": current_ip,
                "lease_time": lease_time,
                "start_time": time.time(),
                "end_time": time.time() + lease_time,
                "xid": xid
            }
            
            # Send ACK
            ack_packet = create_ack(mac, xid, current_ip, lease_time, SERVER_ID)
            log_message(f"Sending DHCPACK for renewal of {current_ip} to {mac} (lease: {lease_time}s)")
            server_socket.sendto(ack_packet, client_address)
            
            # Update lease table display
            update_lease_table_display()
        else:
            # No record of this client
            log_message(f"No existing lease for {mac}, cannot renew")
            # Send NAK
            nak_packet = create_nak(mac, xid, SERVER_ID, "No existing lease found")
            server_socket.sendto(nak_packet, client_address)

def process_release(packet):
    """Process a DHCPRELEASE message."""
    mac = packet["chaddr"]
    xid = packet["xid"]
    
    log_message(f"Received DHCPRELEASE from {mac} (xid: {xid:08X})")
    
    if mac in LEASE_TABLE:
        released_ip = LEASE_TABLE[mac]["ip"]
        del LEASE_TABLE[mac]
        log_message(f"Released IP {released_ip} from {mac}")
        
        # Update lease table display
        update_lease_table_display()
    else:
        log_message(f"No lease found for {mac} to release")

def process_decline(packet):
    """Process a DHCPDECLINE message."""
    mac = packet["chaddr"]
    xid = packet["xid"]
    options = packet.get("options", {})
    
    log_message(f"Received DHCPDECLINE from {mac} (xid: {xid:08X})")
    
    if "requested_ip" in options:
        declined_ip = options["requested_ip"]
        
        # Remove from lease table if present
        if mac in LEASE_TABLE and LEASE_TABLE[mac]["ip"] == declined_ip:
            del LEASE_TABLE[mac]
            
        log_message(f"Client {mac} declined IP {declined_ip} (possibly in use)")
        
        # Update lease table display
        update_lease_table_display()
    else:
        log_message(f"Decline message from {mac} missing requested_ip option")

def process_inform(packet, client_address):
    """Process a DHCPINFORM message."""
    mac = packet["chaddr"]
    xid = packet["xid"]
    ciaddr = packet["ciaddr"]
    
    log_message(f"Received DHCPINFORM from {mac} at {ciaddr} (xid: {xid:08X})")
    
    # Send ACK without lease time
    ack_packet = create_ack(mac, xid, ciaddr, 0, SERVER_ID)
    log_message(f"Sending DHCPACK (inform) to {mac} at {ciaddr}")
    server_socket.sendto(ack_packet, client_address)

def handle_dhcp_message(data, client_address):
    """Parse and process incoming DHCP messages."""
    try:
        packet = parse_packet(data)
        
        if packet:
            message_type = packet["op"]  # The message type is stored in "op" field
            
            if message_type == DHCPDISCOVER:
                process_discover(packet, client_address)
            elif message_type == DHCPREQUEST:
                process_request(packet, client_address)
            elif message_type == DHCPRELEASE:
                process_release(packet)
            elif message_type == DHCPDECLINE:
                process_decline(packet)
            elif message_type == DHCPINFORM:
                process_inform(packet, client_address)
            else:
                log_message(f"Received unknown DHCP message type: {message_type}")
        else:
            log_message("Failed to parse DHCP packet")
    except Exception as e:
        log_message(f"Error processing DHCP message: {e}")

def clean_expired_leases():
    """Remove expired leases from the lease table."""
    current_time = time.time()
    expired_macs = []
    
    for mac, info in LEASE_TABLE.items():
        if current_time > info["end_time"]:
            expired_macs.append(mac)
    
    for mac in expired_macs:
        ip = LEASE_TABLE[mac]["ip"]
        del LEASE_TABLE[mac]
        log_message(f"Lease for {ip} assigned to {mac} has expired")
    
    if expired_macs:
        update_lease_table_display()

def clean_old_offers():
    """Remove offers that have been outstanding for too long."""
    current_time = time.time()
    stale_offers = []
    
    for mac, info in OFFERS.items():
        # Remove offers older than 60 seconds
        if current_time - info["timestamp"] > 60:
            stale_offers.append(mac)
    
    for mac in stale_offers:
        ip = OFFERS[mac]["ip"]
        del OFFERS[mac]
        log_message(f"Offer of {ip} to {mac} has expired")

def maintenance_task():
    """Periodically check for expired leases and stale offers."""
    while True:
        time.sleep(10)
        clean_expired_leases()
        clean_old_offers()

# GUI functions
def log_message(message):
    """Add a message to the log."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    
    # Add to log display (thread-safe)
    if "log_text" in globals() and log_text:
        log_text.after(0, lambda: log_text.insert(tk.END, log_entry + "\n"))
        log_text.after(0, lambda: log_text.see(tk.END))
    
    print(log_entry)  # Also print to console

def update_lease_table_display():
    """Update the lease table display in the GUI."""
    if not lease_tree:
        return
        
    # Clear existing entries
    lease_tree.after(0, lambda: lease_tree.delete(*lease_tree.get_children()))
    
    # Add current leases
    for mac, info in LEASE_TABLE.items():
        ip = info["ip"]
        lease_time = info["lease_time"]
        start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["start_time"]))
        end_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["end_time"]))
        
        # Insert into tree (thread-safe)
        lease_tree.after(0, lambda mac=mac, ip=ip, lease_time=lease_time, 
                            start_time=start_time, end_time=end_time: 
                            lease_tree.insert("", tk.END, values=(mac, ip, lease_time, start_time, end_time)))

def save_leases():
    """Save the current lease table to a file with a digital signature."""
    try:
        serializable_leases = {}
        for mac, info in LEASE_TABLE.items():
            serializable_leases[mac] = {
                "ip": info["ip"],
                "lease_time": info["lease_time"],
                "start_time": info["start_time"],
                "end_time": info["end_time"],
                "xid": info["xid"]
            }
        
        # Convert leases to JSON
        lease_json = json.dumps(serializable_leases, indent=2)
        
        # Sign the JSON data
        signature = sign_json(private_key, serializable_leases)
        
        # Save the lease table to a file
        with open("dhcp_leases.json", "w") as f:
            f.write(json.dumps({
                "leases": serializable_leases,
                "signature": signature
            }, indent=2))
        
        # Save the signature to a separate .sig file
        with open("dhcp_leases.sig", "w") as sig_file:
            sig_file.write(signature)
        
        log_message("Lease table saved to dhcp_leases.json with a digital signature")
    except Exception as e:
        log_message(f"Error saving lease table: {e}")
        messagebox.showerror("Save Error", f"Failed to save lease table: {e}")

def load_leases():
    """Load the lease table from a file and verify its digital signature."""
    try:
        with open("dhcp_leases.json", "r") as f:
            data = json.load(f)
        
        leases = data.get("leases")
        
        # Load the signature from the .sig file
        with open("dhcp_leases.sig", "r") as sig_file:
            signature = sig_file.read()
        
        # Verify the signature
        if not verify_json_signature(public_key, leases, signature):
            log_message("Lease table signature verification failed! Possible tampering detected.")
            messagebox.showerror("Verification Error", "Lease table signature verification failed!")
            return
        
        global LEASE_TABLE
        LEASE_TABLE = leases
        
        log_message("Lease table loaded from dhcp_leases.json and verified successfully")
        update_lease_table_display()
    except FileNotFoundError:
        log_message("No saved lease table found")
    except Exception as e:
        log_message(f"Error loading lease table: {e}")
        messagebox.showerror("Load Error", f"Failed to load lease table: {e}")

def add_static_lease():
    """Add a static lease entry."""
    try:
        mac = simpledialog.askstring("Static Lease", "Enter MAC address (format: 00:11:22:33:44:55):")
        if not mac:
            return
            
        # Validate MAC format
        try:
            parts = mac.split(":")
            if len(parts) != 6 or not all(len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts):
                raise ValueError("Invalid MAC format")
        except:
            messagebox.showerror("Input Error", "Invalid MAC address format")
            return
            
        ip = simpledialog.askstring("Static Lease", f"Enter IP address for {mac}:")
        if not ip:
            return
            
        # Validate IP format and range
        try:
            parts = ip.split(".")
            if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
                raise ValueError("Invalid IP format")
                
            if not ip.startswith(f"{NETWORK_PREFIX}."):
                if not messagebox.askyesno("Warning", f"IP {ip} is outside the configured network {NETWORK_PREFIX}.0/24. Continue anyway?"):
                    return
        except:
            messagebox.showerror("Input Error", "Invalid IP address format")
            return
            
        # Check if IP is already assigned
        for m, info in LEASE_TABLE.items():
            if info["ip"] == ip and m != mac:
                if not messagebox.askyesno("Warning", f"IP {ip} is already assigned to {m}. Override?"):
                    return
                    
        # Add to lease table
        LEASE_TABLE[mac] = {
            "ip": ip,
            "lease_time": DEFAULT_LEASE_TIME,
            "start_time": time.time(),
            "end_time": time.time() + DEFAULT_LEASE_TIME,
            "xid": 0
        }
        
        log_message(f"Added static lease: {mac} -> {ip}")
        update_lease_table_display()
    except Exception as e:
        log_message(f"Error adding static lease: {e}")

def delete_lease():
    """Delete a selected lease."""
    try:
        selection = lease_tree.selection()
        if not selection:
            messagebox.showinfo("Selection", "Please select a lease to delete")
            return
            
        item = lease_tree.item(selection[0])
        mac = item["values"][0]
        
        if mac in LEASE_TABLE:
            ip = LEASE_TABLE[mac]["ip"]
            del LEASE_TABLE[mac]
            log_message(f"Manually deleted lease: {mac} -> {ip}")
            update_lease_table_display()
    except Exception as e:
        log_message(f"Error deleting lease: {e}")

def modify_lease():
    """Modify a selected lease."""
    try:
        selection = lease_tree.selection()
        if not selection:
            messagebox.showinfo("Selection", "Please select a lease to modify")
            return
            
        item = lease_tree.item(selection[0])
        mac = item["values"][0]
        
        if mac in LEASE_TABLE:
            current_ip = LEASE_TABLE[mac]["ip"]
            new_ip = simpledialog.askstring("Modify Lease", f"Enter new IP for {mac} (current: {current_ip}):")
            
            if not new_ip:
                return
                
            # Validate IP format and range
            try:
                parts = new_ip.split(".")
                if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
                    raise ValueError("Invalid IP format")
                    
                if not new_ip.startswith(f"{NETWORK_PREFIX}."):
                    if not messagebox.askyesno("Warning", f"IP {new_ip} is outside the configured network {NETWORK_PREFIX}.0/24. Continue anyway?"):
                        return
            except:
                messagebox.showerror("Input Error", "Invalid IP address format")
                return
                
            # Check if IP is already assigned
            for m, info in LEASE_TABLE.items():
                if info["ip"] == new_ip and m != mac:
                    if not messagebox.askyesno("Warning", f"IP {new_ip} is already assigned to {m}. Override?"):
                        return
            
            # Update lease
            LEASE_TABLE[mac]["ip"] = new_ip
            log_message(f"Modified lease: {mac} -> {new_ip} (was {current_ip})")
            update_lease_table_display()
    except Exception as e:
        log_message(f"Error modifying lease: {e}")

# RSA key generation and signing functions
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_json(private_key, json_data):
    """
    Sign the JSON data using the private key.
    """
    json_bytes = json.dumps(json_data).encode('utf-8')
    signature = private_key.sign(
        json_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_json_signature(public_key, json_data, signature):
    """
    Verify the JSON data's signature using the public key.
    """
    json_bytes = json.dumps(json_data).encode('utf-8')
    signature_bytes = base64.b64decode(signature)
    try:
        public_key.verify(
            signature_bytes,
            json_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        log_message(f"Signature verification failed: {e}")
        return False

def generate_and_save_keys():
    """Generate RSA keys and save them to files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    log_message("RSA keys generated and saved to private_key.pem and public_key.pem")

try:
    private_key = load_private_key()
    public_key = load_public_key()
    log_message("RSA keys loaded successfully")
except FileNotFoundError:
    log_message("RSA keys not found. Generate keys using generate_and_save_keys()")
    generate_and_save_keys()
    private_key = load_private_key()
    public_key = load_public_key()
# Create main window
root = tk.Tk()
root.title("DHCP Server")
root.geometry("800x600")

# Create main frame
main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True)

# Create tabs
tab_control = ttk.Notebook(main_frame)
tab_control.pack(fill=tk.BOTH, expand=True)

# Lease table tab
lease_tab = ttk.Frame(tab_control)
tab_control.add(lease_tab, text="Lease Table")

# Create lease table frame
lease_frame = ttk.Frame(lease_tab)
lease_frame.pack(fill=tk.BOTH, expand=True)

# Create lease table
lease_tree = ttk.Treeview(lease_frame, columns=("MAC", "IP", "Lease Time", "Start Time", "End Time"), 
                          show="headings", selectmode="browse")
lease_tree.heading("MAC", text="MAC Address")
lease_tree.heading("IP", text="IP Address")
lease_tree.heading("Lease Time", text="Lease Time (s)")
lease_tree.heading("Start Time", text="Start Time")
lease_tree.heading("End Time", text="End Time")
lease_tree.column("MAC", width=150)
lease_tree.column("IP", width=120)
lease_tree.column("Lease Time", width=80)
lease_tree.column("Start Time", width=150)
lease_tree.column("End Time", width=150)
lease_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add scrollbar to lease table
lease_scroll = ttk.Scrollbar(lease_frame, orient="vertical", command=lease_tree.yview)
lease_scroll.pack(side=tk.RIGHT, fill=tk.Y)
lease_tree.configure(yscrollcommand=lease_scroll.set)

# Create button frame
button_frame = ttk.Frame(lease_tab)
button_frame.pack(fill=tk.X, padx=5, pady=5)

# Add buttons
add_button = ttk.Button(button_frame, text="Add Static", command=add_static_lease)
add_button.pack(side=tk.LEFT, padx=5)

delete_button = ttk.Button(button_frame, text="Delete", command=delete_lease)
delete_button.pack(side=tk.LEFT, padx=5)

modify_button = ttk.Button(button_frame, text="Modify", command=modify_lease)
modify_button.pack(side=tk.LEFT, padx=5)

save_button = ttk.Button(button_frame, text="Save Leases", command=save_leases)
save_button.pack(side=tk.LEFT, padx=5)

load_button = ttk.Button(button_frame, text="Load Leases", command=load_leases)
load_button.pack(side=tk.LEFT, padx=5)

# Log tab
log_tab = ttk.Frame(tab_control)
tab_control.add(log_tab, text="Server Log")

# Create log text widget
log_text = scrolledtext.ScrolledText(log_tab, wrap=tk.WORD)
log_text.pack(fill=tk.BOTH, expand=True)

# Settings tab
settings_tab = ttk.Frame(tab_control)
tab_control.add(settings_tab, text="Settings")

# Create settings frame
settings_frame = ttk.LabelFrame(settings_tab, text="DHCP Server Settings")
settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Add settings
ttk.Label(settings_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
ttk.Label(settings_frame, text=SERVER_ID).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

ttk.Label(settings_frame, text="Network Prefix:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
ttk.Label(settings_frame, text=NETWORK_PREFIX).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

ttk.Label(settings_frame, text="IP Range:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
ttk.Label(settings_frame, text=f"{NETWORK_PREFIX}.{IP_RANGE_START} - {NETWORK_PREFIX}.{IP_RANGE_END}").grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

ttk.Label(settings_frame, text="Default Lease Time:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
ttk.Label(settings_frame, text=f"{DEFAULT_LEASE_TIME} seconds").grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)

ttk.Label(settings_frame, text="Min Lease Time:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
ttk.Label(settings_frame, text=f"{MIN_LEASE_TIME} seconds").grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)

ttk.Label(settings_frame, text="Max Lease Time:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
ttk.Label(settings_frame, text=f"{MAX_LEASE_TIME} seconds").grid(row=5, column=1, sticky=tk.W, padx=5, pady=5)

# Status bar
status_var = tk.StringVar()
status_var.set("Server ready")
status_bar = ttk.Label(main_frame, textvariable=status_var, relief=tk.SUNKEN, anchor=tk.W)
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

def start_server():
    try:
        server_socket.bind(('', 67))  # Standard DHCP server port
        log_message(f"DHCP Server started on {SERVER_ID}:67")
        status_var.set(f"Server running on {SERVER_ID}:67")
        
        # Start the maintenance thread
        maintenance_thread = threading.Thread(target=maintenance_task, daemon=True)
        maintenance_thread.start()
        
        # Start listening for DHCP messages
        listen_thread = threading.Thread(target=listen_for_dhcp, daemon=True)
        listen_thread.start()
    except Exception as e:
        log_message(f"Error starting server: {e}")
        status_var.set("Server failed to start")
        messagebox.showerror("Server Error", f"Failed to start DHCP server: {e}")

def listen_for_dhcp():
    """Listen for incoming DHCP messages."""
    log_message("Listening for DHCP messages...")
    
    while True:
        try:
            data, client_address = server_socket.recvfrom(4096)
            # Start a new thread to handle this message
            processing_thread = threading.Thread(target=handle_dhcp_message, args=(data, client_address), daemon=True)
            processing_thread.start()
        except Exception as e:
            log_message(f"Error receiving DHCP message: {e}")

# Start server when application starts
root.after(1000, start_server)

def on_closing():
    """Handle application closing."""
    if messagebox.askokcancel("Quit", "Do you want to save the lease table before quitting?"):
        save_leases()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

# Start the main event loop
root.mainloop()