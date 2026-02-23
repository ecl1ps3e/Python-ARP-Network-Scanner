import scapy.all as scapy


def scan(ip_range):
    print(f"[*] Scanning network: {ip_range}...")

    # 1. Create an ARP request packet asking for the IP range
    arp_request = scapy.ARP(pdst=ip_range)

    # 2. Create an Ethernet frame directed to the broadcast MAC address (ff:ff:ff:ff:ff:ff)
    # This ensures the physical switch sends our packet to EVERY device on the network
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # 3. Stack the packets together (Ethernet Frame wraps the ARP Packet)
    arp_request_broadcast = broadcast / arp_request

    # 4. Send the packet and capture the responses
    # srp = Send and Receive Packets (at Layer 2 - Data Link Layer)
    # timeout=2: Wait 2 seconds for replies. verbose=False: Hide Scapy's default spam text.
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    # 5. Parse the raw network data into a clean dictionary
    clients_list = []
    for element in answered_list:
        # element[0] is our request, element[1] is their reply
        # psrc = Packet Source IP, hwsrc = Hardware Source MAC
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(results_list):
    print("\nLive Devices Found:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}")


def main():
    print("--- Active Network Reconnaissance Tool ---")

    # To scan a whole network, you add /24 to the base IP.
    target_network = input("Enter Target Subnet (e.g., 192.168.0.1/24 or 10.0.0.1/24): ")

    if not target_network:
        print("[-] Target cannot be empty.")
        return

    results = scan(target_network)

    if len(results) == 0:
        print("[-] No devices found. Check your subnet or run as Administrator.")
    else:
        print_result(results)


if __name__ == "__main__":
    main()