# CSN150-Final-Project
"NetGuard"  Combining "network" and "guard," suggesting a tool for monitoring and controlling network traffic. This script combines packet sniffing, blocking based on an IP range, It serves as a foundation that you can customize based on your specific requirements for network traffic analysis and control.

import scapy.all as scapy
import logging

#Importing Libraries:
#import scapy.all as scapy: Imports the Scapy library, a powerful packet manipulation tool. Import logging: Imports the Python logging module for logging information.

def block_ip(ip_address):
    # Add your blocking logic here
    print(f"Blocked traffic from {ip_address}")
#Blocking Function:
#block_ip(ip_address): This function is a placeholder for the blocking logic. It currently prints a message indicating that traffic from a specific IP address has been blocked.

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"[*] Detected IP packet from {ip_src} to {ip_dst}")

        # Specify the IP range to block (replace with your range)
        start_ip = '128.204.0.0'
        end_ip = '128.204.127.255'

        # Check if the source IP is within the specified range
        if start_ip <= ip_src <= end_ip:
            block_ip(ip_src)

        # Display more packet information
        print(packet.summary())
        print(packet.show())

        # Log packet information
        logging.info(f"Detected IP packet from {ip_src} to {ip_dst}")
#Packet Callback Function:
#packet_callback(packet): This function is called for each captured packet. It checks if the packet has an IP layer using packet.haslayer(scapy.IP). Extracts source (ip_src) and destination (ip_dst) IP addresses #from the IP layer. Prints a message indicating the detection of an IP packet. Specifies an IP range (start_ip to end_ip) and checks if the source IP is within this range. If true, it calls the block_ip function.
#Displays more detailed information about the packet using packet.summary() and packet.show(). Logs information about the detected packet using the Python logging module.

# Set the network interface to 'Wi-Fi' or the appropriate identifier
network_interface = 'Wi-Fi'

#Network Interface Setting: Specifies the network interface to sniff. In this case, it's set to 'Wi-Fi'. Ensure that this matches the actual network interface on your system.

# Configure logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO)
#Logging Configuration: Configures the logging module to write log messages to a file named 'packet_log.txt' at the INFO level.

# Start sniffing on the specified network interface
scapy.sniff(iface=network_interface, prn=packet_callback, store=0)
#Packet Sniffing: Initiates packet sniffing on the specified network interface ('Wi-Fi'). Calls the packet_callback function for each captured packet.store=0 is used to prevent storing packets in memory, which is #useful for continuous packet capture.

