#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h> /*ntop_inet*/
#include <sys/types.h>
#include <ifaddrs.h>

/*
[리포트]
sender(victim)의 arp table을 변조하라.
[프로그램]
send_arp <interface> <sender ip> <target ip>
ex : send_arp wlan0 192.168.10.2 192.168.10.1
sender ip는 victim ip라고도 함.
target ip는 일반적으로 gateway임.
[학습]
구글링을 통해서 arp header의 구조(각 필드의 의미)를 익힌다.

pcap_sendpacket 함수를 이용해서 user defined buffer를 packet으로 전송하는 방법을 익힌다.
attacker(자신) mac 정보를 알아 내는 방법은 구글링을 통해서 코드를 베껴 와도 된다.
arp infection packet 구성에 필요한 sender mac 정보는 프로그램 레벨에서 자동으로(정상적인 arp request를 날리고 그 arp reply를 받아서) 알아 오도록 코딩한다.
최종적으로 상대방을 감염시킬 수 있도록 eth header와 arp header를 구성하여 arp infection packet을 보내고 sender에서 target arp table이 변조되는 것을 확인해 본다.
[리포트 제목]
char track[] = "취약점"; // "특기병", "컨설팅", "포렌식"
char name[] = "홍길동";
printf("[bob6][%s]send_arp[%s]", track, name);
[제출 기한]
2017.08.01 05:59
[ps]
소스 코드는 가급적 C, C++(다른 programming language에 익숙하다면 그것으로 해도 무방).
bob@gilgil.net 계정으로 자신의 git repository 주소를 알려 줄 것.
절대 BoB access point 네트워크를 대상으로 테스트하지 말 것. 하려면 허니팟을 띄워 하거나 BoBMil 이라는 access point(암호는 BoB access point와 동일)를 사용할 것.
 */

#define NET_INF_LEN	50
#define ARP_PADDING	18

#define ETH_IP		0x0008
#define ETH_ARP		0x0608



/* Function Declaration */

int 	getMacAddress(char * interface, char * buf);
void 	get_remote_mac_address(char * ip);
void	arp_request(pcap_t * handle, char * mymac, uint8_t * targetip);

/* Function Declaration */



/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};


#define ARP_REQUEST 0x0100	/* ARP Request */
#define ARP_REPLY	0x0200	/* ARP Reply */
typedef struct arp_header
{
	u_int16_t	htype;	 /* Hardware Type */
	u_int16_t	ptype;	 /* Protocol Type */
	u_char		hlen;	 /* Hardware Address Length */
	u_char		plen;	 /* Protocol Address Length */
	u_int16_t	oper;	 /* Operation Code */
	u_char 		sha[6];	 /* Sender MAC address */
	u_char 		spa[4];	 /* Sender IP address */
	u_char 		tha[6];	 /* Target MAC address */
	u_char 		tpa[4];	 /* Target IP address */
};

typedef struct {
	unsigned char	eth_dst[6];
	unsigned char	eth_src[6];
	unsigned short	eth_type;

	unsigned short	arp_ethtype;
	unsigned short	arp_iptype;
	unsigned char	arp_ethlen;
	unsigned char	arp_iplen;
	unsigned short	arp_op;
	unsigned char	arp_srceth[6];
	unsigned char	arp_srcip[4];
	unsigned char	arp_dsteth[6];
	unsigned char	arp_dstip[4];
	unsigned char	padding[ARP_PADDING];
} arp_hdr;


unsigned char * ethbroadcast = "\xff\xff\xff\xff\xff\xff";
unsigned char	ethnull[] = {0, 0, 0, 0, 0, 0};


int main(int argc,  char * argv[])
{


	FILE * fd;
	char address[16];			/* variable for check whether valid ipv4 address */
	int result;					/* variable for storing some functions */
	char mac_addr[16];			/* variable for mac address */
	uint8_t mac_address[6];		/* variable for mac address */

	uint8_t sender_ip[4];
	uint8_t target_ip[4];


    char error_buffer[PCAP_ERRBUF_SIZE];    /* for printing error string */


    pcap_t * handle;	/* create handle */


	/* check argv */
	if (argc < 4)
	{
		printf("[-] Usage : send_arp <interface> <sender ip> <target ip>\n");
		printf("[-] E.g : ex : send_arp wlan0 192.168.10.2 192.168.10.1\n");
		return 1;
	}


	/* Network Interface : Length limit */
	if (strlen(argv[1]) > NET_INF_LEN)
	{
		printf("[-] Error : Network Interface must not exceed 50 characters.\n");
		return 1;
	}

    /* if return value is -1, argv[1] is invalid network interface */
	result = getMacAddress(argv[1], mac_addr);
	if (result == -1)
	{
		return 1;
	}



	/* check whether ip address is valid */
	/* sender ip */
	result = inet_pton(AF_INET, argv[2], address);
	if (result == -1)
	{
		printf("[-] Your argv[2] : '%s'\n", argv[2]);
		printf("\tIs it valid IPv4 address?\n");

		return 1;
	}

	inet_aton(argv[2], sender_ip);

	/* target ip */
	result = inet_pton(AF_INET, argv[3], address);
	if (result == -1)
	{
		printf("[-] Your argv[3] : '%s'\n", argv[2]);
		printf("\tIs it valid IPv4 address?\n");
	}

	inet_aton(argv[2], target_ip);

	printf("[*] Network Interface : %s\n", argv[1]);
	printf("[*] Mac Address : %s\n", mac_addr);
	sscanf(mac_address, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_addr[0], &mac_addr[1], &mac_addr[2], &mac_addr[3], &mac_addr[4], &mac_addr[5]);



	/* open network device */
	handle = pcap_open_live(argv[1], 100, 1, 1000, error_buffer);
	if (handle == NULL)
	{
		printf("[-] Can not open your network device : %s\n", error_buffer);
		return 1;
	}


	arp_request(handle, mac_address, target_ip);



	return 0;
}






int getMacAddress(char * interface, char * buf)
{
	char network_interface[NET_INF_LEN];
	char address_file[NET_INF_LEN + strlen("/sys/class/net//address")];

	FILE *fd;

	/* get network interface from argv */
	strncpy(network_interface, interface, NET_INF_LEN-1);
	network_interface[NET_INF_LEN - 1] = '\0';

	/* get mac address from this file */
	sprintf(address_file, "/sys/class/net/%s/address", network_interface);

	/* file open success */
	if (fd = fopen(address_file, "r"))
	{
		fscanf(fd, "%s", buf);
		fclose(fd);
	}

	/* file open failed */
	else
	{
		printf("[-] '%s' isn't the Network Interface.\n", interface);
		return -1;
	}



	return 0;
}


void get_remote_mac_address(char * ip)
{

}

void arp_request(pcap_t * handle, char * mymac, uint8_t * targetip)
{
	arp_hdr pkt;

	memcpy(pkt.eth_dst, ethbroadcast, 6);
	memcpy(pkt.eth_src, mymac, 6);

	pkt.eth_type = ETH_ARP;

	pkt.arp_ethtype	= 0x0100;
	pkt.arp_iptype 	= ETH_IP;
	pkt.arp_ethlen 	= 6;
	pkt.arp_iplen 	= 4;

	pkt.arp_op = 0x0100;

	memcpy(pkt.arp_srceth, mymac, 6);
	memcpy(pkt.arp_srcip, "\xc0\xa8\x34\x86", 4);
	memcpy(pkt.arp_dsteth, ethnull, 6);
	memcpy(pkt.arp_dstip, targetip, 4);
	memset(pkt.padding, 0, ARP_PADDING);

	if ( pcap_sendpacket(handle, (unsigned char *)&pkt, sizeof(pkt)) != 0)
	{
		fprintf(stderr, "[*] Error  \n", pcap_geterr(handle));
	}

}



