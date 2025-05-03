# DHCP Client-Server Simulation in Python

This project is a Python-based simulation of the Dynamic Host Configuration Protocol (DHCP), following the principles of [RFC 2131] and [RFC 2132]. It implements a custom DHCP server and client using UDP sockets, with RSA cryptographic signatures for message integrity.

---

## 🧪 Features

- DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK flow
- Lease management with T1 (50%) and T2 (87.5%) timers
- RSA signature verification for packet authenticity
- Custom JSON-based packet format
- Multi-threaded lease handling
- Timeout and rebinding support
- Terminal-based client and server

---

## 📂 Project Structure

dhcp-project/
├── client.py          # DHCP client
├── server.py          # DHCP server
├── dhcp_common.py     # Shared logic (packet creation, RSA signing)
└── README.md          # This file

---
## ⚙️ Requirements

Install all required libraries via pip:

pip install cryptography


---

## ▶️ How to Run

### Run the Server (first):

bash
python server.py

or try (Linux)
bash
python3 server.py


Server listens on UDP port 67 and responds to client requests.

---

### Run the Client:

bash
python client.py

or try (Linux)
bash
python3 server.py


Client initiates DHCPDISCOVER on UDP port 68, requests an IP, and manages lease renewal.

---

## 🔐 Security

Messages are signed using **RSA private keys** and verified by the server using the public key.

- Keys are generated automatically if not found.
- Signature ensures packets weren’t tampered with.

---

## 📡 Protocol Overview

1. **DHCPDISCOVER**: Client broadcasts request.
2. **DHCPOFFER**: Server offers IP address.
3. **DHCPREQUEST**: Client requests offered IP.
4. **DHCPACK**: Server confirms allocation.
5. Lease renewal via **T1/T2** timers.

---

## 🧪 Example Packet Format
```json
json
{
  "op": "DHCPDISCOVER",
  "xid": 12345678,
  "chaddr": "aa:bb:cc:dd:ee:ff",
  "ciaddr": "0.0.0.0",
  "yiaddr": null,
  "siaddr": null,
  "timestamp": 1714781543.5827,
  "options": {
    "requested_ip": "192.168.1.100",
    "server_identifier": "192.168.1.1"
  }
}
```
---
## 🎥 Demo Video
- Server Running at Windows
- Clients running at :
    1. Windows 
    2. Kali Linux(Virtual Box)
    2. Ubuntu (Virtual Box)
[Watch Demo](https://vimeo.com/1081162440/0755e48d91)
[Watch Tamper-Testing](https://vimeo.com/1081162887/caf6939513)
