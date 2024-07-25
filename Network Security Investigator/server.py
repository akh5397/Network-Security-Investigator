import logging
import subprocess
import ipaddress
import time
import re
import threading
import nmap
import pyfiglet
from scapy.all import traceroute
from scapy.all import *

# Suppress non-error Scapy messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
from scapy.all import *

# Generate DHCP Discover packet
def generate_dhcp_discover(interface):
    hw = get_if_raw_hwaddr(interface)[1]
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=hw) / DHCP(options=[("message-type", "discover"), ("client_id", hw), "end"])
    return dhcp_discover

# Sniff DHCP Offer packets
def sendpthread(packet,iface,verbose):
    time.sleep(2)
    sendp(packet, iface=iface , verbose=True)
    print("thread working")
    
def sniff_dhcp_offer(dhcp_discovera,interface):
    #sendp(dhcp_discovera, iface=interface, verbose=True)
    userserverid = input("ENTER AUTHENTIC SERVER IP")
    print("\nSniffing DHCP Offers on interface:", interface)
    def packet_callback(packet):
        if DHCP in packet and packet[DHCP].options[0][1] == 2:  # DHCP Offer
            print("\n--- DHCP Offer Received ---")
            print("Source IP:", packet[IP].src)
            print("Offered IP:", packet[BOOTP].yiaddr)
            options = packet[DHCP].options
            server_id = None
            for option in options:
                if option[0] == "message-type":
                    print("Message Type:", option[1])  # Option 53
                elif option[0] == "server_id":
                    server_id = option[1]
                    if(userserverid==server_id):
                     print("Authentic server")                     
                    else:
                     print("Rogue server")
                    print("Server ID:", server_id)  # Option 54
    

    t1=threading.Thread(target=sendpthread,args=(dhcp_discovera,interface, True))
    t1.start()
    sniff(iface=interface, prn=packet_callback, filter="udp and (port 67 or port 68)", timeout=60)
    t1.join()
    print("print statement")
   #sendp(dhcp_discovera, iface=interface, verbose=True)

def find_active_hosts(network_ips, max_repetitions=1,break_after=10):
    active_hosts = []
    count=0
    for network_ip in network_ips:
        subnet = ipaddress.ip_network(network_ip)
        for ip in subnet.hosts():
            repetitions = 0
            
            while repetitions < max_repetitions:
                command = ['ping', '-c', '1', '-n', str(ip)]  # Ping each IP address once
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode == 0:
                    active_hosts.append(str(ip))
                    print(f"{ip} is active.")
                    repetitions +=1
                    count += 1
                else:
                    count += 1
                    repetitions +=1
                    print(f"{ip} is not active.")
            if count>= break_after:
               break
        if count >= break_after:
            break  # Exit the loop after reaching the break_after limit
    return active_hosts

def enumerate_device(ip_address):
    # Create an nmap PortScanner object
    nm = nmap.PortScanner() 
    # Define the nmap scan options
    scan_options = {
        '-sV': 'Attempts to determine the version of the service running on port',
        '-sS': 'TCP SYN port scan (Default)',
        '-sT': 'TCP connect port scan (Default without root privilege)',
        '-sU': 'UDP port scan',
        '-sA': 'TCP ACK port scan',
        '-sW': 'TCP Window port scan',
        '-O': 'Remote OS detection using TCP/IP stack fingerprinting'
    }

    # Perform each nmap scan and log/print the results
    with open(f"{ip_address}_scan_results.txt", "a") as log_file:
        log_file.write(f"Scan results for {ip_address}:\n")
        for option, description in scan_options.items():
            log_file.write(f"\nNmap scan option: {option}\nDescription: {description}\n")
            nm.scan(ip_address, arguments=option)
            log_file.write(f"Hosts: {nm.all_hosts()}\n")
            for host in nm.all_hosts():
                log_file.write(f"Host: {host}\n")
                log_file.write(f"State: {nm[host].state()}\n")
                for proto in nm[host].all_protocols():
                    log_file.write(f"Protocol: {proto}\n")
                    ports = nm[host][proto].keys()
                    for port in ports:
                        log_file.write(f"Port: {port}\tState: {nm[host][proto][port]['state']}\n")
                        print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
    print("CHECK THE LOG FILE FOR DETALS")
    # Scan the IP address using various nmap options
    nm.scan(ip_address, arguments='-A -T4')  # Example: aggressive scan, timing template 4

    # Print scan results
    print(f"Scan results for {ip_address}:")
    for host in nm.all_hosts():
        print(f"Host: {host}")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
    
    res, unans = traceroute([ip_address], dport=[80,443], maxttl=10, retry=-2)
    # graph traceroute results:")
    res.graph()

def packet_sniff(net_iface): 
# Asking the user for the number of packets to sniff ( the "count" parameter)
# input packet in number
 net_iface=net_iface
 while True:
     try:
         pkt_to_sniff = int(input(
             "* Enter the number of packets to capture ( 0 is infinity): "))
         break
     except ValueError:
         print("Please input integer only...")
         continue

#  Considering teh case when the user enters 0 (infinity)
 if int(pkt_to_sniff) != 0:
     print("\nThe program will caputer %d packets. \n" % int(pkt_to_sniff))
 elif int(pkt_to_sniff) == 0:
     print("\nThe program will caputer packets until the timeout expires. \n")

# Asking the user for the time interval to sniff (the "timeout" parameter)
 """
 pkt_to_sniff and time_to_sniff will work together to control the sniffer: 
 for example: if the user enterd 10 pkt to sniff and the time is 2 sec the prog will capture as much 
 it can then when the time end it will stop the sniff. or if the user want to caputer 1 pkt and the
 time is 100 sec the program will stop after it get the 1 pkt, this to control the sniffing priod. 
 """
 
 
 # input time in number
 while True:
     try:
         time_to_sniff = int(
             input("* Enter the number of second to run the caputer: "))
         if int(time_to_sniff) != 0:
             print("\nThe program will caputer packets fro %d seconds.\n" %
                   int(time_to_sniff))
         break
     except ValueError:
         print("Please input integer only...")
         continue

 ''' Asking the user to enter which protocol he want to apply the sniffing process
 for example he can chose ARP ICMP or BOOP
 '''

 # This will check the user input if it is one of the option and if the user enter the value in capital it will convert the input in to lowercase
 options = ["arp", "icmp", "bootP", "0", "http"]
 while True:
     try:
         proto_sniff = input(
             "\nEnter the protocol name you want to filetr by[ ARP| ICMP| BOOTP | http or 0 is for all]: ").lower()
         if (proto_sniff in options):
            print("protocols found ")
            break
         else:
             print("protocol not found")
     except:
         continue

 # Considerign the case when the user enters 0 (meaning all protocols)

 if (proto_sniff == "arp") or (proto_sniff == "icmp") or (proto_sniff == "bootp"):
     print("\nThe program will captureonly %s packets.\n" % proto_sniff.upper())
 elif (proto_sniff) == "0":
     print("\nThe progam will capture all protocols. \n")

 # Asking the user to enter the name and path of th elog file to be created
 file_name = input("Pleas give a name to the log file: ")
 
 # Creating the text fiel (if it doesn't exist) for the packet logging and/or opening if for appending
 sniff_log = open(file_name, "a")
 
 # This function will be called for each captered packet, and then it will extract
 # parmeters from the packet then log eacn packt to the log file created before

 def paket_log(packet):
 
     # Getting the current timestamp
     now = datetime.now()
 
     # Writting the packet info to the log file, considering the protocol the user want or 0 for all
     # # writing the data to the log first will read the packet then add it to the log file
     if proto_sniff == "http":
         # this filter will check if the packet has HTTP will print the packet
         if packet.haslayer(http.HTTPRequest):
             if packet.haslayer(Raw):  # tthe password stored in the raw field
                 # this filter to store and print the load
                 load = str(packet[Raw].load)
                 keyword = ['usernmae', 'user', 'login', 'password', 'pass']
                 for key in keyword:
                     if key in load:
                         print('\nHere you will find the userName and the Password:\n\n-___ ' +
                               str(load)+'_--', file=sniff_log)
                         break
 
     elif (proto_sniff == "arp") or (proto_sniff == "icmp") or (proto_sniff == "bootp"):
         print("Time: " + str(now) + "Protocol: " + proto_sniff.upper() + " The Source MAC: " +
               packet[0].src + " The Destination MAC: " + packet[0].dst, file=sniff_log)
 
     else:
         print("Time: " + str(now) + "All protocols: " + " The Source MAC is: " +
               packet[0].src + " The Destination MAC is:" + packet[0].dst, file=sniff_log)
 
 
 print("\nStarting the capturing......")


 # Runnignteh sniffing process (with or without a filter)
 if proto_sniff == "0" or proto_sniff == "http":
     sniff(iface=net_iface, count=int(pkt_to_sniff),
           timeout=int(time_to_sniff), prn=paket_log)
     print("Done Capturing all protocols.")
 
 elif (proto_sniff == "arp") or (proto_sniff == "icmp") or (proto_sniff == "bootp"):
     sniff(iface=net_iface, filter=proto_sniff, count=int(
         pkt_to_sniff), timeout=int(time_to_sniff), prn=paket_log)
     print("Done Capturing %s protocol." % proto_sniff)
 
 else:
     print("\nCould not identify the protocol :( .... ")
     sys.exit()
 
 # printing the closing messages
 print("\nPlease check the file %s file to see the captured packets.\n" % file_name)

def run_server():
    # Get the number of clients from the user
    num_clients = int(input("Enter the number of clients: "))

    # Create an empty list to store client information
    client_list = []

    # Get client information from the user
    for i in range(num_clients):
        client_ip = input(f"Enter IP address of client {i+1}: ")
        client_port = int(input(f"Enter port of client {i+1}: "))
        client_list.append((client_ip, client_port))

    # Create a UDP socket for server communication
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the server IP and port
    server_ip = '0.0.0.0'  # Listen on all available interfaces
    server_port = 12345  # Choose a port for server communication
    server_socket.bind((server_ip, server_port))

    # Send the "start" command to each client
    for client_ip, client_port in client_list:
        server_socket.sendto("start".encode(), (client_ip, client_port))
        print(f"Sent 'start' command to {client_ip}:{client_port}.")

    # Receive data from each client
    for client_ip, client_port in client_list:
        print(f"Waiting for data from {client_ip}:{client_port}...")
        data, client_address = server_socket.recvfrom(1024)
        print(f"Received data from {client_address}:")
        print(data.decode())

    # Close the server socket
    server_socket.close()
    

# Main function
def main():
    result = pyfiglet.figlet_format("Ak.Rogue.tool", font="banner3-D")
    print(result)
    # Select interface from the list
    cmd = "ip link show up | grep -oP '(?<=: ).*(?=: <)'"
    ifconfig = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ifconfig.communicate()
    interfaceInString = output[0].decode("utf-8")
    inetfInSplitList = interfaceInString.split("\n")
    print('\n'.join(['{}  ->  {}'.format(i, val)
                    for i, val in (enumerate(inetfInSplitList, start=1))]))
    print("\nThese are all the active interfaces in your system.  \n")

    while True:
        try:
            net_iface = input("Select Interface from the list: ")
            if (net_iface in inetfInSplitList):
                print("Interface[ %s ] Exists" % net_iface)
                break
            else:
                print("Interface[ %s ] Not Exists" % net_iface)
        except:
            continue
    print("\n[+] The Interface You have selected is:", net_iface)

    # Generate and send DHCP Discover packet
    
    dhcp_discover = generate_dhcp_discover(net_iface)
    sendp(dhcp_discover, iface=net_iface, verbose=False)

    
    while True:
        print("\nMenu:")
        print("1. Find Rogue DHCP Server")
        print("2. Find DHCP SERVER IN DIFFERENT NETWORK USING CLIENT AGENT")
        print("3. Find Active Devices (Inventory)")
        print("4. Enumerate a Device")
        print("5. Network Packet Sniffer for Various Protocols")
        print("6. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            # Ask for authentic DHCP server IP address
            #as_ip = input("\nEnter the IP Address of the Authentic DHCP Server: ")

            # Generate and send DHCP Discover packet
            print("\nSending DHCP Discover packet on interface:", net_iface)
            dhcp_discover = generate_dhcp_discover(net_iface)
           
            # Sniff DHCP packets and log to file
            sniff_dhcp_offer(dhcp_discover,net_iface)

        elif choice == "2":
              run_server()
        elif choice == "3":
            
            network_ips = input("Enter network IPs (seperated by space): ").split()
            active_hosts = find_active_hosts(network_ips, max_repetitions=1, break_after=10)
            print("Active hosts found:", active_hosts)

        elif choice == "4":
            device_ip = input("\nEnter the IP Address from Active devices to enumerate: ")
            enumerate_device(device_ip)

        elif choice == "5":
            packet_sniff(net_iface)

        elif choice == "6":
            print("Exiting program...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
