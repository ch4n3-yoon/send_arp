CC = gcc

pcap_test : send_arp.c
gcc -o pcap_test pcap_test.c -lpcap -w