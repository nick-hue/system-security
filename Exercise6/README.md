ΗΡΥ 413 Assignment: 6
AM: 2019030190 Nikolaos Angelidis  
AM: 2019030201 Chrysiis Manoudaki

In order to run our program: 
$sudo snort -c simple.rules -r <pcap_file_name.pcap> -A cmp > output.txt

<pcap_file_name.pcap>: test_pcap_5mins.pcap - sshguess.pcap 

1. Report any icmp connection attempt in test_pcap_5mins.pcap
- Rule: alert icmp any any -> any any (msg:"ICMP connection attempt."; sid:1000010;)
- This rule has the unique Snort ID of 1000010.
- We scan for icmp packets from any source ip address and port and any destination ip address and port. 
- if a icmp connection was attempted we display the message 'ICMP connection attempt.' 

2. Find all packets which contain "hello" string in test_pcap_5mins.pcap
- Rule: alert ip any any -> any any (msg:"'hello' was found."; content:"hello"; sid:1000020;)
- This rule has the unique Snort ID of 1000020.
- We scan for any type of packet (ip) from any source ip address and port and any destination ip address and port.
- if the content of the packet contains the string 'hello' alert with the according message.

3. Report all traffic between non root ports (port number > 1024)
- alert ip any ![1:1024] -> any ![1:1024] (msg:"Non root port found."; sid:1000030;)
- This rule has the unique Snort ID of 1000030.
- We scan for any type of packet (ip) from any source and destination ip address but if the source or destination port
- is not included in the range of 1 to 1024 (root ports), alert with the according message.

4. Create a rule that will detect ssh brute force attacks in sshguess.pcap file

○ A brute force attempt can be realized as 10 attempts within 10 minutes
● Setup the community rules (run snort with associated snort.conf) and report any clear
indicator of malicious traffic in test_pcap_5mins.pcap
○ Some community rules clearly state the exploit detected