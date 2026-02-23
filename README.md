# Active ARP Network Reconnaissance Tool

## 🚩 Overview
A custom network mapping utility built in Python. This tool performs Layer 2 (Data Link) network discovery by broadcasting forged ARP requests to identify all active host IPs and their corresponding physical MAC addresses on a local subnet.

## ⚙️ Technical Mechanisms
* **Raw Packet Crafting:** Utilizes the `scapy` library to manually construct Ethernet frames and ARP payload packets.
* **Broadcast Targeting:** Targets the `ff:ff:ff:ff:ff:ff` MAC address to ensure physical network switches distribute the packet to all connected interfaces.
* **Asynchronous Sniffing:** Sends requests and actively listens for replies on the wire, parsing the raw binary response into a structured data format.

## 🛠️ Tech Stack
* **Language:** Python 3
* **Libraries:** `scapy`
* **Networking:** Layer 2/3 OSI Manipulation, ARP Protocol, IPv4/Subnetting
