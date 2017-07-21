pcap_test:pcap.o
	gcc -o pcap pcap.o -lpcap
pcap.o:pcap.c
	gcc -c -o pcap.o pcap.c


