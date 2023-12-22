ΗΡΥ 413 Assignment: 6  
AM: 2019030190 Nikolaos Angelidis  
AM: 2019030201 Chrysiis Manoudaki  

# In order to run our program: 
- $sudo $myPath/snort -c $myPath/snort.lua -q -R simple.rules -r <pcap_file_name.pcap> -A cmg

- $sudo $myPath/snort -c $myPath/snort.lua -q -R snort3-community.rules -r <pcap_file_name.pcap> -A cmg

- <pcap_file_name.pcap>: test_pcap_5mins.pcap - sshguess.pcap 

## 1. Report any icmp connection attempt in test_pcap_5mins.pcap
### Rule: alert icmp any any -> any any (msg:"ICMP connection attempt."; sid:1000010;)
- This rule has the unique Snort ID of 1000010.
- We scan for icmp packets from any source ip address and port and any destination ip address and port. 
- if a icmp connection was attempted we display the message 'ICMP connection attempt.' 
- Example of result:
01/25-20:54:19.161403 [**] [1:1000010:1] "ICMP connection attempt" [**] [Priority: 0] {ICMP} 10.0.2.2 -> 10.0.2.15
52:54:00:12:35:02 -> 08:00:27:CC:3F:1B type:0x800 len:0xCA
10.0.2.2 -> 10.0.2.15 ICMP TTL:255 TOS:0xC0 ID:65381 IpLen:20 DgmLen:188
Type:11  Code:0  TTL EXCEEDED IN TRANSIT
** ORIGINAL DATAGRAM DUMP:
10.0.2.15:48575 -> 10.0.2.2:1900 UDP TTL:1 TOS:0x0 ID:34664 IpLen:20 DgmLen:160
Len: 132  Csum: 48365
(132 more bytes of original packet)
** END OF DUMP

snort.raw[140]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
BD BF 07 6C 00 8C BC ED  4D 2D 53 45 41 52 43 48  ...l.... M-SEARCH
20 2A 20 48 54 54 50 2F  31 2E 31 0D 0A 48 4F 53   * HTTP/ 1.1..HOS
54 3A 20 32 33 39 2E 32  35 35 2E 32 35 35 2E 32  T: 239.2 55.255.2
35 30 3A 31 39 30 30 0D  0A 4D 41 4E 3A 20 22 73  50:1900. .MAN: "s
73 64 70 3A 64 69 73 63  6F 76 65 72 22 0D 0A 4D  sdp:disc over"..M
58 3A 20 32 0D 0A 53 54  3A 20 75 72 6E 3A 73 63  X: 2..ST : urn:sc
68 65 6D 61 73 2D 75 70  6E 70 2D 6F 72 67 3A 73  hemas-up np-org:s
65 72 76 69 63 65 3A 57  41 4E 49 50 43 6F 6E 6E  ervice:W ANIPConn
65 63 74 69 6F 6E 3A 31  0D 0A 0D 0A              ection:1 ....
etc...


## 2. Find all packets which contain "hello" string in test_pcap_5mins.pcap
### Rule: alert ip any any -> any any (msg:"'hello' was found."; content:"hello"; sid:1000020;)
- This rule has the unique Snort ID of 1000020.
- We scan for any type of packet (ip) from any source ip address and port and any destination ip address and port.
- if the content of the packet contains the string 'hello' alert with the according message.
- Example of the two results found:
01/25-20:55:11.137818 [**] [1:10000020:0] "Hello String Found" [**] [Priority: 0] {TCP} 70.37.129.34:80 -> 10.0.2.15:2553

http_inspect.http_version[8]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
48 54 54 50 2F 31 2E 31                           HTTP/1.1 
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

http_inspect.http_stat_code[3]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
32 30 30                                          200
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

http_inspect.http_stat_msg[2]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
4F 4B                                             OK
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - - etc...

01/25-20:57:01.137818 [**] [1:10000020:0] "Hello String Found" [**] [Priority: 0] {TCP} 70.37.129.34:5480 -> 10.0.2.15:2553

http_inspect.http_version[8]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
48 54 54 50 2F 31 2E 31                           HTTP/1.1 
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

http_inspect.http_stat_code[3]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
32 30 30                                          200
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

http_inspect.http_stat_msg[2]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
4F 4B                                             OK
etc...

## 3. Report all traffic between non root ports (port number > 1024)
### Rule: alert ip any ![1:1024] <> any ![1:1024] (msg:"Non root port found."; sid:1000030;)
- This rule has the unique Snort ID of 1000030.
- We scan for any type of bidirectional packet (ip) from any source and destination ip address but if the source or destination port
- is not included in the range of 1 to 1024 (root ports), alert with the according message.
- Example of result:

01/25-20:54:16.493610 [**] [1:1000030:0] "Non root port found." [**] [Priority: 0] {TCP} 64.4.9.254:1863 -> 10.0.2.15:2527
52:54:00:12:35:02 -> 08:00:27:CC:3F:1B type:0x800 len:0xF2
64.4.9.254:1863 -> 10.0.2.15:2527 TCP TTL:64 TOS:0x0 ID:65277 IpLen:20 DgmLen:228
***AP*** Seq: 0x5F520810  Ack: 0x5163E9F1  Win: 0x2238  TcpLen: 20

01/25-20:54:16.493674 [**] [1:1000030:0] "Non root port found." [**] [Priority: 0] {TCP} 10.0.2.15:2527 -> 64.4.9.254:1863
08:00:27:CC:3F:1B -> 52:54:00:12:35:02 type:0x800 len:0x36
10.0.2.15:2527 -> 64.4.9.254:1863 TCP TTL:128 TOS:0x0 ID:34587 IpLen:20 DgmLen:40 DF
***A**** Seq: 0x5163E9F1  Ack: 0x5F5208CC  Win: 0xFA26  TcpLen: 20

## 4. Create a rule that will detect ssh brute force attacks in sshguess.pcap file
### Rule: alert ip any any -> any 22 (msg:"SSH Brute Force Attack"; flow:to_server,established; detection_filter:track by_src, count 10, seconds 600; sid:1000040;)
- This rule has the unique Snort ID of 1000040.
- We scan for any type of packet (ip) from any source ip address and port and any destination ip address but for destination port 22 for ssh.
### - Rule arguments: 
#### **flow**
* to_server: Match on client requests
* established: Match only on established TCP connections
#### **detection_filter**
* detection_filter : is used to require multiple rule hits before generating an "event". It triggers an alert only for a specific amount of occurunces (count = 10) in a specific time frame (seconds = 600 = 10 minutes) 
* track by_src : we track (count) the amount of times a specific source ip address appears.

- Example of result:
03/30-16:44:49.238228 [**] [1:1000040:0] "SSH Brute Force Attack" [**] [Priority: 0] {TCP} 192.168.56.1:55470 -> 192.168.56.103:22
0A:00:27:00:00:00 -> 08:00:27:20:54:03 type:0x800 len:0x52
192.168.56.1:55470 -> 192.168.56.103:22 TCP TTL:64 TOS:0x0 ID:34927 IpLen:20 DgmLen:68 DF
***AP*** Seq: 0x4D0A8C11  Ack: 0x8C001964  Win: 0x1000  TcpLen: 32
TCP Options (3) => NOP NOP TS: 657412520 15695

snort.raw[16]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
00 00 00 0C 0A 15 00 00  00 00 00 00 00 00 00 00  ........ ........
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

03/30-16:44:49.275611 [**] [1:1000040:0] "SSH Brute Force Attack" [**] [Priority: 0] {TCP} 192.168.56.1:55470 -> 192.168.56.103:22
0A:00:27:00:00:00 -> 08:00:27:20:54:03 type:0x800 len:0x7A
192.168.56.1:55470 -> 192.168.56.103:22 TCP TTL:64 TOS:0x0 ID:39308 IpLen:20 DgmLen:108 DF
***AP*** Seq: 0x4D0A8C21  Ack: 0x8C001964  Win: 0x1000  TcpLen: 32
TCP Options (3) => NOP NOP TS: 657412557 15707

## 5. Setup the community rules (run snort with associated snort.conf) and report any clear indicator of malicious traffic in test_pcap_5mins.pcap
- We check the classification to detect the malicious traffic. Below are some examples of malicious traffic:

01/25-20:54:37.330025 [**] [1:1990:7] "POLICY-SOCIAL Microsoft MSN user search" [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 10.0.2.15:2550 -> 64.4.35.57:1863
08:00:27:CC:3F:1B -> 52:54:00:12:35:02 type:0x800 len:0x52
10.0.2.15:2550 -> 64.4.35.57:1863 TCP TTL:128 TOS:0x0 ID:34898 IpLen:20 DgmLen:68 DF
***AP*** Seq: 0x7ADFD643  Ack: 0x5F85CA51  Win: 0xFAA1  TcpLen: 20

snort.raw[28]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
43 41 4C 20 31 20 72 61  6B 73 6C 69 63 65 40 68  CAL 1 ra kslice@h
6F 74 6D 61 69 6C 2E 63  6F 6D 0D 0A              otmail.c om..
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

01/25-20:55:44.511002 [**] [1:1411:21] "PROTOCOL-SNMP public access udp" [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 192.168.3.131:52400 -> 192.168.3.99:161
40:61:86:9A:F1:F5 -> 00:04:00:81:81:D0 type:0x800 len:0x78
192.168.3.131:52400 -> 192.168.3.99:161 UDP TTL:128 TOS:0x0 ID:13337 IpLen:20 DgmLen:106
Len: 78

snort.raw[78]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
30 4C 02 01 00 04 06 70  75 62 6C 69 63 A0 3F 02  0L.....p ublic.?.
02 03 5A 02 01 00 02 01  00 30 33 30 0F 06 0B 2B  ..Z..... .030...+
06 01 02 01 19 03 02 01  05 01 05 00 30 0F 06 0B  ........ ....0...
2B 06 01 02 01 19 03 05  01 01 01 05 00 30 0F 06  +....... .....0..
0B 2B 06 01 02 01 19 03  05 01 02 01 05 00        .+...... ......
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

