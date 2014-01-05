//reader.h
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include "bootp.h"

/*IP address*/
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/*ARP header*/
#define ARP_REQUEST 1 /* ARP Request */
#define ARP_REPLY 2 /* ARP Reply */
struct arp {
    u_int16_t htype; /* Hardware Type */
    u_int16_t ptype; /* Protocol Type */
    u_char hlen; /* Hardware Address Length */
    u_char plen; /* Protocol Address Length */
    u_int16_t oper; /* Operation Code */
    u_char sha[6]; /* Sender hardware address */
    u_char spa[4]; /* Sender IP address */
    u_char tha[6]; /* Target hardware address */
    u_char tpa[4]; /* Target IP address */
};

void getHour(const struct pcap_pkthdr* header,int verbose);
void getHeaderLength(const struct pcap_pkthdr* header,int verbose);
void packetDisplay(const struct pcap_pkthdr * header,const u_char *packet, int verbose);
int readEthernet(struct ether_header* ethernet,int verbose);
void readApplicatif(char * appli,const struct pcap_pkthdr* header, const u_char * packet, int offset, int verbose);
void printf_notohs(char * text,u_char  * content);
void readIP(const struct pcap_pkthdr * header, const u_char * packet,int offset,int verbose);
void readBootP(const struct pcap_pkthdr * header, const u_char * packet, int offset, int verbose);
void readTCP(const struct pcap_pkthdr * header,const u_char * packet,int offset,int verbose);
void readUDP(struct udphdr* udp,int verbose);
void readU_Char(const u_char * toRead,int length,int verbose);
void readARP(struct arp * arp, int verbose);
void print_ip(const u_char * ip);
	
