all: pcap_ex

pcap_ex: pcap_ex.c pcap_ex.h 
	gcc pcap_ex.c -g -o pcap_ex -lpcap

run: pcap_ex
	./pcap_ex

clean:
	rm -rf pcap_ex
