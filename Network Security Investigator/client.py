import logging
import subprocess
import re
import socket
import netifaces
import threading

# Function to listen for commands from the server
def listen_for_commands():
    while True:
        command, server_address = client_socket.recvfrom(1024)
        command = command.decode().strip().lower()
        
        if command == "start":
            print("Received start command from the server. Starting DHCP server detection...")
            start_detection()

# Function to start DHCP server detection
def start_detection():
# Detecting Rogue DHCP servers per interface (except the loopback interface)
    interfaces = netifaces.interfaces()
    print(interfaces)
    for interface in interfaces:
        if interface != "lo":
            #Getting the hardware address
            hw = get_if_raw_hwaddr(interface)[1]

            #Creating the DHCP Discover packet
            dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=hw) / DHCP(options=[("message-type", "discover"), "end"])

            #Sending the Discover packet and accepting multiple answers for the same Discover packet
            ans, unans = srp(dhcp_discover, multi=True, iface=interface, timeout=5, verbose=0)

            ans.show()
            #Defining a dictionary to store mac-ip pairs
            mac_ip = {}

            for pair in ans:
                mac_ip[pair[1][Ether].src] = pair[1][IP].src

            if ans:
                # Prepare the data to send and print
                data = f"\n--> The following DHCP servers found on the {interface} LAN:\n"

                for mac, ip in mac_ip.items():
                    data += f"IP Address: {ip}, MAC Address: {mac}\n"

                # Print the data
                print(data)

                # Send data to the server
                client_socket.sendto(data.encode(), (server_ip, 12345))  # Assuming port 12345

            else:
                # Send a message indicating no active DHCP servers found and print
                no_servers_msg = f"\n--> No active DHCP servers found on the {interface} LAN.\n"
                print(no_servers_msg)
                client_socket.sendto(no_servers_msg.encode(), (server_ip, 12345))  # Assuming port 12345

#Importing Scapy and handling the ImportError exception
try:
    from scapy.all import *

except ImportError:
    print("Scapy is not installed on your system.")
    print("Try using: sudo pip3.8 install scapy")
    sys.exit()

#This will suppress all messages that have a lower level of seriousness than error messages.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

#Setting the checkIPaddr parameter to False
conf.checkIPaddr = False

# Get the server IP from the user
server_ip = input("Enter the server IP address: ")

# Create a UDP socket for client communication
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#Bind the socket to the client IP and port
client_ip = '0.0.0.0' #Listen on all available iinterfaces
client_port = 12345 # use port 12345 for client communication
client_socket.bind((client_ip, client_port))

# Start the command listening thread
command_listener_thread = threading.Thread(target=listen_for_commands)
command_listener_thread.daemon = True
command_listener_thread.start()

# Main loop to wait for commands
while True:
    pass  # This loop keeps the program running until terminated
