# Network-Security-Investigator
Network Security Investigator is a comprehensive toolkit designed to help identify potential security risks on a network. It provides functionalities such as rogue DHCP server detection, active device discovery, device enumeration, and network packet sniffing.

Features
Rogue DHCP Server Detection: Identify unauthorized DHCP servers that could potentially distribute incorrect network configurations. This includes the ability to use a client agent for detection in separate networks.
Active Device Discovery: Find active devices (inventory) on a specific network segment.
Device Enumeration: Enumerate services using nmap, provide a graphical representation of the route traversed, and log the data.
Network Packet Sniffing: Capture and analyze network traffic for various protocols, including filtering for specific protocols and potentially capturing sensitive information like usernames and passwords (if transmitted unencrypted).
Installation
Clone the repository:

sh
Copy code
git clone https://github.com/your-username/network-security-investigator.git
cd network-security-investigator
Install the required dependencies:

sh
Copy code
pip install -r requirements.txt
Install Scapy (if not installed):

sh
Copy code
sudo pip install scapy
Install nmap (if not installed):

sh
Copy code
sudo apt-get install nmap
Usage
Server Side:

Run the server script to start the server and manage client communication.

sh
Copy code
python server.py
Follow the prompts to enter the number of clients and their IP addresses and ports.

Client Side:

Run the client script to start the DHCP server detection.

sh
Copy code
python client.py
Enter the server IP address when prompted.

Main Toolkit:

Run the main toolkit script.

sh
Copy code
python main.py
Select the desired interface and follow the menu options to use different functionalities such as rogue DHCP server detection, active device discovery, device enumeration, and network packet sniffing.

Technologies Used
Programming Languages: Python
Libraries: Scapy, nmap, pyfiglet, netifaces, subprocess, threading, logging, socket
Tools: Wireshark (optional for packet analysis)
Contributing
Contributions are welcome! Please fork the repository, create a branch for your feature or bug fix, and submit a pull request for review.
