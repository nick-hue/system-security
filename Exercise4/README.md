By running the Makefile with: 
make

the executable file will be generated for the execution of our program. 
There are 2 different main ways of executing the program.
1. Online: monitor the traffic live from a network interface saving info about the files captured into a text file named log.txt
Run with : ./pcap_ex -i <device_name> 

2.  Offline: read a pcap file, to print outputs of the packets captured into the terminal
Run with : /pcap_ex -r <packet_capture_file_name> 

You can make use of the [-f] Filter expression in string format (e.g., port 8080) in order
to filter out the packets you want to capture.

Usage:
./pcap_ex -i <device_name> -f <filter_expression>
./pcap_ex -r <packet_capture_file_name> -f <filter_expression>

Examples:
./pcap_ex -i eth0 
./pcap_ex -r test_pcap_5mins.pcap
./pcap_ex -i eth0 -f "port 8080"