# File: client.py

import socket
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
import threading
import time
import json
from dhcp_common import *

# Socket setup with longer timeout for network communication
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.settimeout(5)  # 5 second timeout

# Global variables
MAC = get_mac()
ASSIGNED_IP = ""
REQUESTED_IP = ""
LEASE = 0
SERVER_IP = "255.255.255.255"  # Default to broadcast
SERVER_PORT = 67  # Standard DHCP port
SERVER_ID = ""
TRANSACTION_ID = None
DHCP_STATE = "INIT"  # DHCP client state machine
STATE_COLORS = {
    "INIT": "#D3D3D3",      # Light Gray
    "SELECTING": "#FFF59D",  # Light Yellow
    "REQUESTING": "#FFCC80", # Light Orange
    "BOUND": "#A5D6A7",      # Light Green
    "RENEWING": "#90CAF9",   # Light Blue
    "REBINDING": "#CE93D8",  # Light Purple
    "RELEASING": "#EF9A9A"   # Light Red
}

def set_server_ip():
    global SERVER_IP
    new_ip = simpledialog.askstring("Server IP", "Enter DHCP Server IP (use 255.255.255.255 for broadcast):", 
                                   initialvalue=SERVER_IP)
    if new_ip:
        SERVER_IP = new_ip
        update_status_display()
        log_message(f"Server address set to: {SERVER_IP}")

def set_state(new_state):
    global DHCP_STATE
    old_state = DHCP_STATE
    DHCP_STATE = new_state
    log_message(f"State changed: {old_state} -> {new_state}")
    update_status_display()
    state_frame.config(bg=STATE_COLORS.get(new_state, "#FFFFFF"))
    state_label.config(bg=STATE_COLORS.get(new_state, "#FFFFFF"), text=f"State: {new_state}")

def discover():
    """Send DHCPDISCOVER message to find available DHCP servers."""
    global TRANSACTION_ID, SERVER_IP
    
    set_state("SELECTING")
    TRANSACTION_ID = generate_xid()  # Generate new transaction ID
    
    try:
        # Always ensure broadcast is enabled for DISCOVER
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Always use broadcast address for discovery
        broadcast_address = ("255.255.255.255", SERVER_PORT)
        packet = create_discover(MAC, TRANSACTION_ID)
        
        log_message(f"Broadcasting DHCPDISCOVER (xid: {TRANSACTION_ID:08X}) to find servers")
        client_socket.sendto(packet, broadcast_address)
        
        # Wait for DHCPOFFER
        receive_offer()
        
    except socket.timeout:
        log_message("Timeout waiting for DHCPOFFER - no DHCP servers responded")
        set_state("INIT")
    except Exception as e:
        log_message(f"Error during DISCOVER: {str(e)}")
        set_state("INIT")

def receive_offer():
    """Receive and process DHCPOFFER messages."""
    global REQUESTED_IP, SERVER_ID, SERVER_IP
    
    log_message("Waiting for DHCPOFFER...")
    
    try:
        data, server = client_socket.recvfrom(1024)
        response = parse_packet(data)
        
        if response["op"] == DHCPOFFER and response["xid"] == TRANSACTION_ID:
            REQUESTED_IP = response["yiaddr"]
            if "options" in response and "server_identifier" in response["options"]:
                SERVER_ID = response["options"]["server_identifier"]
                # Update the SERVER_IP to match the server that responded
                SERVER_IP = SERVER_ID
                update_status_display()
                log_message(f"Server discovered at {SERVER_IP}")
            else:
                SERVER_ID = server[0]  # Use the sender's IP if not specified
                SERVER_IP = SERVER_ID  # Update the SERVER_IP
                update_status_display()
                log_message(f"Server discovered at {SERVER_IP} (from sender address)")
                
            lease_time = response["options"].get("ip_address_lease_time", "unknown")
            
            log_message(f"Received DHCPOFFER: IP={REQUESTED_IP}, Server={SERVER_ID}, Lease={lease_time}s")
            
            # Send DHCPREQUEST to accept the offer
            send_request()
        else:
            log_message(f"Received non-offer or mismatched transaction ID")
            set_state("INIT")
            
    except socket.timeout:
        log_message("DHCPOFFER timed out - no servers responded")
        set_state("INIT")
    except Exception as e:
        log_message(f"Error receiving offer: {str(e)}")
        set_state("INIT")

def send_request():
    """Send DHCPREQUEST message to request the offered IP address."""
    set_state("REQUESTING")
    
    try:
        # For the REQUEST, we still broadcast to ensure all servers see it
        server_address = ("255.255.255.255", SERVER_PORT)
        packet = create_request(MAC, TRANSACTION_ID, REQUESTED_IP, SERVER_ID)
        
        log_message(f"Sending DHCPREQUEST for {REQUESTED_IP}")
        
        # Make sure broadcast is enabled
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client_socket.sendto(packet, server_address)
        
        # Wait for DHCPACK
        receive_acknowledgement()
        
    except socket.timeout:
        log_message("Timeout sending DHCPREQUEST")
        set_state("INIT")
    except Exception as e:
        log_message(f"Error during REQUEST: {str(e)}")
        set_state("INIT")

def receive_acknowledgement():
    """Receive and process DHCPACK or DHCPNAK messages."""
    global ASSIGNED_IP, LEASE
    
    log_message("Waiting for server acknowledgement...")
    
    try:
        data, server = client_socket.recvfrom(1024)
        response = parse_packet(data)
        
        if response["op"] == DHCPACK and response["xid"] == TRANSACTION_ID:
            ASSIGNED_IP = response["yiaddr"]
            if "options" in response and "ip_address_lease_time" in response["options"]:
                LEASE = response["options"]["ip_address_lease_time"]
            else:
                LEASE = 3600  # Default to 1 hour if not specified
                
            log_message(f"Received DHCPACK: IP={ASSIGNED_IP}, Lease={LEASE}s")
            set_state("BOUND")
            update_status_display()
            start_lease_timer(LEASE)
            
        elif response["op"] == DHCPNAK and response["xid"] == TRANSACTION_ID:
            log_message(f"Received DHCPNAK: {response.get('options', {}).get('message', 'No reason given')}")
            set_state("INIT")
            ASSIGNED_IP = ""
            LEASE = 0
            update_status_display()
            
        else:
            log_message(f"Received invalid response type or wrong transaction ID")
            set_state("INIT")
            
    except socket.timeout:
        log_message("Server acknowledgement timed out")
        set_state("INIT")
    except Exception as e:
        log_message(f"Error receiving acknowledgement: {str(e)}")
        set_state("INIT")

def renew():
    """Renew the current IP address lease."""
    global TRANSACTION_ID
    
    if not ASSIGNED_IP or DHCP_STATE not in ["BOUND", "RENEWING"]:
        log_message("Cannot renew: No valid IP assignment or not in correct state")
        return
        
    set_state("RENEWING")
    TRANSACTION_ID = generate_xid()  # New transaction ID for renewal
    
    try:
        # For renewal, communicate directly with the leasing server
        server_address = (SERVER_ID, SERVER_PORT)
        
        # Create a unicast DHCPREQUEST for renewal
        packet = create_request(MAC, TRANSACTION_ID, ASSIGNED_IP, SERVER_ID)
        
        log_message(f"Sending renewal DHCPREQUEST for {ASSIGNED_IP}")
        client_socket.sendto(packet, server_address)
        
        # Wait for DHCPACK or DHCPNAK
        receive_acknowledgement()
        
    except socket.timeout:
        log_message("Renewal timeout, entering rebinding state")
        set_state("REBINDING")
        # Should attempt rebinding here (broadcast to any server)
        rebind()
    except Exception as e:
        log_message(f"Error during renewal: {str(e)}")

def rebind():
    """Attempt to rebind with any available DHCP server."""
    global TRANSACTION_ID
    
    if not ASSIGNED_IP:
        log_message("Cannot rebind: No IP assignment")
        return
        
    set_state("REBINDING")
    TRANSACTION_ID = generate_xid()
    
    try:
        # Enable broadcast
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Broadcast DHCPREQUEST to any server
        server_address = ("255.255.255.255", SERVER_PORT)
        packet = create_request(MAC, TRANSACTION_ID, ASSIGNED_IP, "0.0.0.0")  # No specific server
        
        log_message(f"Broadcasting rebind DHCPREQUEST for {ASSIGNED_IP}")
        client_socket.sendto(packet, server_address)
        
        # Wait for DHCPACK or DHCPNAK
        receive_acknowledgement()
        
    except socket.timeout:
        log_message("Rebinding timeout, lease expired")
        set_state("INIT")
        ASSIGNED_IP = ""
        LEASE = 0
        update_status_display()
    except Exception as e:
        log_message(f"Error during rebinding: {str(e)}")

def release():
    """Release the current IP address."""
    global TRANSACTION_ID, ASSIGNED_IP, LEASE
    
    if not ASSIGNED_IP or not SERVER_ID:
        log_message("Cannot release: No valid IP or server")
        return
        
    set_state("RELEASING")
    TRANSACTION_ID = generate_xid()
    
    try:
        server_address = (SERVER_ID, SERVER_PORT)
        packet = create_release(MAC, TRANSACTION_ID, ASSIGNED_IP, SERVER_ID)
        
        log_message(f"Sending DHCPRELEASE for {ASSIGNED_IP}")
        client_socket.sendto(packet, server_address)
        
        # No response expected for DHCPRELEASE
        old_ip = ASSIGNED_IP
        ASSIGNED_IP = ""
        LEASE = 0
        update_status_display()
        log_message(f"Released IP {old_ip}")
        set_state("INIT")
        
    except Exception as e:
        log_message(f"Error releasing IP: {str(e)}")

def request_new_ip():
    """Release current IP if any and request a new one."""
    if ASSIGNED_IP:
        release()
        # Wait a moment for the server to process the release
        root.after(500, discover)
    else:
        discover()

def update_status_display():
    """Update all information displays in the GUI."""
    ip_label.config(text=f"IP: {ASSIGNED_IP if ASSIGNED_IP else 'None'}")
    
    if LEASE > 0:
        lease_label.config(text=f"Lease Time: {format_lease(LEASE)}")
    else:
        lease_label.config(text="Lease Time: None")
        
    server_display.config(text=f"Server: {SERVER_IP}:{SERVER_PORT}")
    
    if SERVER_ID:
        server_id_label.config(text=f"DHCP Server ID: {SERVER_ID}")
    else:
        server_id_label.config(text="DHCP Server ID: None")

def start_lease_timer(initial_lease):
    """Start the lease timer with T1 (renewal) and T2 (rebind) timers."""
    global lease_timer_thread
    
    # Reset any existing timer
    if 'lease_timer_thread' in globals() and lease_timer_thread.is_alive():
        lease_timer_thread.do_run = False
        
    # Calculate RFC standard timers
    t1 = int(initial_lease * 0.5)  # 50% of lease time - attempt renewal
    t2 = int(initial_lease * 0.875)  # 87.5% of lease time - attempt rebind
    
    lease_timer_thread = threading.Thread(
        target=lease_countdown, 
        args=(initial_lease, t1, t2),
        daemon=True
    )
    lease_timer_thread.do_run = True
    lease_timer_thread.start()

def lease_countdown(initial_lease, t1, t2):
    """Countdown the lease and manage transitions between DHCP states."""
    global LEASE
    
    LEASE = initial_lease
    remaining = initial_lease
    thread = threading.current_thread()
    
    log_message(f"Lease timer started: {format_lease(initial_lease)}")
    log_message(f"T1 (Renewal): {format_lease(t1)}, T2 (Rebind): {format_lease(t2)}")
    
    while remaining > 0 and getattr(thread, "do_run", True):
        time.sleep(1)
        remaining -= 1
        LEASE = remaining
        
        # Update GUI from main thread
        root.after(0, lambda: lease_label.config(text=f"Lease Time: {format_lease(remaining)}"))
        
        # T1 timer - attempt renewal
        if remaining == initial_lease - t1:
            root.after(0, lambda: log_message("T1 reached - initiating lease renewal"))
            root.after(0, renew)
            
        # T2 timer - attempt rebind
        elif remaining == initial_lease - t2:
            root.after(0, lambda: log_message("T2 reached - initiating rebinding"))
            root.after(0, rebind)
            
        # Lease expired
        if remaining == 0:
            root.after(0, lambda: log_message("Lease expired!"))
            root.after(0, lambda: set_state("INIT"))
            root.after(0, lambda: ip_label.config(text="IP: None"))
            root.after(0, lambda: lease_label.config(text="Lease Time: None"))

def log_message(message):
    """Add message to the log display with timestamp."""
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, f"[{timestamp}] {message}\n")
    log_text.see(tk.END)
    log_text.config(state=tk.DISABLED)

def save_log():
    """Save the current log contents to a file."""
    try:
        filename = f"dhcp_client_log_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(log_text.get(1.0, tk.END))
        messagebox.showinfo("Log Saved", f"Log saved to {filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save log: {str(e)}")

def clear_log():
    """Clear the log display."""
    log_text.config(state=tk.NORMAL)
    log_text.delete(1.0, tk.END)
    log_text.config(state=tk.DISABLED)

# GUI
root = tk.Tk()
root.title("DHCP Client")
root.geometry("650x500")
root.minsize(600, 500)

# Main container
main_container = tk.Frame(root)
main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Top frame with state display
state_frame = tk.Frame(main_container, bg=STATE_COLORS["INIT"], bd=2, relief=tk.GROOVE)
state_frame.pack(fill=tk.X, pady=(0, 10))

state_label = tk.Label(state_frame, text="State: INIT", font=("Arial", 12, "bold"), 
                      bg=STATE_COLORS["INIT"], padx=10, pady=5)
state_label.pack(side=tk.LEFT)

server_display = tk.Label(state_frame, text=f"Server: {SERVER_IP}:{SERVER_PORT}", 
                         font=("Arial", 10), bg=STATE_COLORS["INIT"], padx=10)
server_display.pack(side=tk.RIGHT, padx=10, pady=5)

# Client info section
info_frame = tk.LabelFrame(main_container, text="DHCP Client Information", padx=10, pady=10)
info_frame.pack(fill=tk.X, pady=(0, 10))

mac_label = tk.Label(info_frame, text=f"MAC: {MAC}", font=("Arial", 10))
mac_label.grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)

ip_label = tk.Label(info_frame, text="IP: None", font=("Arial", 10, "bold"))
ip_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

server_id_label = tk.Label(info_frame, text="DHCP Server ID: None", font=("Arial", 10))
server_id_label.grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)

lease_label = tk.Label(info_frame, text="Lease Time: None", font=("Arial", 10))
lease_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

# Control buttons
btn_frame = tk.Frame(main_container)
btn_frame.pack(fill=tk.X, pady=(0, 10))

btn_discover = tk.Button(btn_frame, text="Discover", command=discover, width=12)
btn_discover.pack(side=tk.LEFT, padx=5)

btn_renew = tk.Button(btn_frame, text="Renew", command=renew, width=12)
btn_renew.pack(side=tk.LEFT, padx=5)

btn_release = tk.Button(btn_frame, text="Release", command=release, width=12)
btn_release.pack(side=tk.LEFT, padx=5)

btn_new_ip = tk.Button(btn_frame, text="Get New IP", command=request_new_ip, width=12)
btn_new_ip.pack(side=tk.LEFT, padx=5)

btn_set_server = tk.Button(btn_frame, text="Set Server", command=set_server_ip, width=12)
btn_set_server.pack(side=tk.RIGHT, padx=5)

# Log section
log_frame = tk.LabelFrame(main_container, text="Client Log")
log_frame.pack(fill=tk.BOTH, expand=True)

log_text = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED, height=15)
log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Log control buttons
log_btn_frame = tk.Frame(main_container)
log_btn_frame.pack(fill=tk.X, pady=(5, 0))

btn_save_log = tk.Button(log_btn_frame, text="Save Log", command=save_log)
btn_save_log.pack(side=tk.LEFT, padx=5)

btn_clear_log = tk.Button(log_btn_frame, text="Clear Log", command=clear_log)
btn_clear_log.pack(side=tk.LEFT, padx=5)

# Initialize
log_message(f"DHCP Client initialized. MAC: {MAC}")
log_message(f"Default server: {SERVER_IP}:{SERVER_PORT}")
set_state("INIT")

root.mainloop()