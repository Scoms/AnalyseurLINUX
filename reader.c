//reader.c
#include "reader.h"

#define LOW 1
#define MID 2
#define HIG 3

//Valeurs  
#define IP 8
#define ARP 1544
#define RARP 56710
#define BIG 1
#define SMALL 0

//Protocoles
#define TCP_PROT 0x0600
#define UDP_PROT 0x1100

#define HTTP 80
#define HTTPS 443
#define DHCP1 44
#define DHCP2 43
#define DNS 53
#define FTP_ETA 20
#define FTP_TRANS 21
#define POP2 109
#define POP3 110
#define SMTP 25
#define IMAP 143
#define IMAPSSL 993
#define SCTP 22
#define BOOTPC 68
#define BOOTPS 67
#define DNS1 28001
#define DNS2 8805



void packetDisplay(const struct pcap_pkthdr * header,const u_char *packet,int verbose){

	if(verbose == HIG){
		readU_Char(packet,header->len,BIG);
	}

	struct ether_header *ethernet;
	struct ip *ip;
	struct arp *arp;

	int size_ethernet = sizeof(struct ether_header);

	ethernet = (struct ether_header*)(packet);;
	int eth_type = readEthernet(ethernet,verbose);
	u_char destPort;

	// Decision sur le protocole 
	switch(ntohs(eth_type)){
		case ETHERTYPE_IP:
			readIP(header,packet,size_ethernet,verbose);
			break;
		case ETHERTYPE_ARP:	
			arp = (struct arp*)(packet + size_ethernet);
			readARP(arp,verbose);
			break;
		case ETHERTYPE_REVARP:
			readApplicatif("RARP",header,packet, (sizeof(*arp)+sizeof(*ip)),verbose);		
			break;
		default:
			printf("%x\n",ntohs(eth_type) );
			printf("--------------------------------ERROR IN ETHERNET INTERPRETATION ----------------------------------\n");
			exit(1);
			break;
	}
}

void readARP(struct arp* arp, int verbose){
	if(verbose == 3){
		printf("ARP\n");
		printf("  Hard Type : %i\n",arp->htype);
		printf("  Prot Type : %i\n",arp->ptype);
		printf("  Hard Add len : %x\n",arp->hlen);
		printf("  Hard Prot Len : %x\n",arp->plen);
		printf("  Ope Code : %i\n",arp->oper);
		printf("  Sender hardware address :");
		readU_Char(arp->sha,sizeof(arp->sha),SMALL);
		printf("  Sender IP address :");
		ip_address * spa = (ip_address *)arp->spa;
		printf("%d.%d.%d.%d\n",spa->byte1,spa->byte2,spa->byte3,spa->byte4);
		printf("  Target hardware address :");
		readU_Char(arp->tha,sizeof(arp->tha),SMALL);
		printf("  Target IP address :");
		ip_address * tpa = (ip_address *)arp->tpa;
		printf("%d.%d.%d.%d\n",tpa->byte1,tpa->byte2,tpa->byte3,tpa->byte4);	
	}
	else if (verbose == MID){
		printf("ARP\n");
		printf("  Sender hardware address :");
		readU_Char(arp->sha,sizeof(arp->sha),SMALL);
		printf("  Sender IP address :");
		ip_address * spa = (ip_address *)arp->spa;
		printf("%d.%d.%d.%d\n",spa->byte1,spa->byte2,spa->byte3,spa->byte4);
		printf("  Target hardware address :");
		readU_Char(arp->tha,sizeof(arp->tha),SMALL);
		printf("  Target IP address :");
		ip_address * tpa = (ip_address *)arp->tpa;
		printf("%d.%d.%d.%d\n",tpa->byte1,tpa->byte2,tpa->byte3,tpa->byte4);
	}
	else{
		printf("ARP");
	}
}

// permet d'afficher des u_char proprement
void readU_Char(const u_char * toRead,int length,int type){
	int i = 0;
	char suite[16];
	char toPrint;
	for(i=0; i < length; i++){
		toPrint = toRead[i];
		// si c'est un gros contenu on le display en colonne par groupe de 4 
		// Sinon en une seul ligne par groupe de 2 
		if(type == BIG){
			if(!isprint(toPrint))
				toPrint = '.';
			suite[i%16] = toPrint;
			if((i%16 == 0 && i != 0)){
				printf("  %s\n",suite);
				//bzero(suite,16);
			}
		}
				
		printf("%02x", (toRead[i])) ;
		if(type == SMALL)
			printf(" ");
		else
			if(i%2 == 1 && i != 0)
				printf(" ");

		if(type == BIG){
			if((i == length -1)){
			int j ;
			for(j= i % 16; j < 17; j++){
				if(j!= 16){
				if(j%2 == 0)
					printf("   ");
				else
					printf("  ");

				}
			}
			//printf("    ");
			for (j=0; j< (i%16+1); j++){
				printf("%c",suite[j]);
			}
		}
		}
	}
	printf("\n");
}

int readEthernet(struct ether_header* ethernet,int verbose){
	if(verbose == HIG || verbose == MID){
		printf("\nEthernet : \n");
		printf("  Destination : ");
		readU_Char(ethernet->ether_dhost,sizeof(ethernet->ether_dhost),SMALL);
		printf("  Source : ");
		readU_Char(ethernet->ether_shost,sizeof(ethernet->ether_shost),SMALL);
	}
	if(verbose == LOW){
		printf("Ethernet, ");
	}
	// printf("%i\n", ethernet->ether_type);
	return ethernet->ether_type;
}


void readIP(const struct pcap_pkthdr* header,const u_char* packet,int offset,int verbose){
	struct ip * ip = (struct ip*)(packet + offset);
	if(verbose == 3){
		printf("IP : \n");
		printf("  Version : %x\n",ip->ip_v);	
		printf("  HL : %x\n",ip->ip_hl);	
		printf("  Total length : %d\n",ntohs(ip->ip_len));	
		printf("  ID : %d\n",ntohs(ip->ip_id));	
		printf("  Offset : %d\n",ntohs(ip->ip_off));	
		printf("  TOS : %d\n",ntohs(ip->ip_tos));	
		printf("  Protocole : %d\n",ntohs(ip->ip_p));	
		printf("  Total : %d\n",ntohs(ip->ip_ttl));	
		printf("  Checksum : %d\n",ntohs(ip->ip_sum));	
		printf("  IP src : %s\n",inet_ntoa(ip->ip_src));	
		printf("  IP dest : %s\n",inet_ntoa(ip->ip_dst));	
	}
	else if(verbose == 2){
		printf("IP : \n");
	}
	if(verbose == 1){
		printf("IP, ");
	}

	offset += sizeof(*ip);		
	struct tcphdr* tcp;
	struct udphdr* udp;
	switch(ntohs(ip->ip_p)){
		case TCP_PROT:;
			readTCP(header,packet,offset,verbose);
			break;
		case UDP_PROT:
			udp = (struct udphdr*)(ip + sizeof(ip));
			offset += sizeof(*udp);
			readUDP(header,packet,udp,offset,verbose);
			char * appli = "Applicatif";
			if(udp->source == DHCP1 || udp->source == DHCP2)
				appli = "DHCP";
			//readApplicatif("Applicatif",header,packet,offset,SMALL);
			break;
		default:
			printf("%x\n",ntohs(ip->ip_p));
			printf("Protocole non traité : %i\n",ip->ip_p);
			exit(1);
			break;
	}
}

void readBootP(const struct pcap_pkthdr * header, const u_char * packet, int offset, int verbose){
	struct bootp * bootp = (struct bootp *)(packet + offset);
	if(verbose == HIG){
		printf("BOOTP : \n");
		printf("  OpCode : %d\n",ntohs(bootp->bp_op));
		printf("  Hard addr type : %d\n",ntohs(bootp->bp_htype));
		printf("  Hard addr length : %d\n",ntohs(bootp->bp_hlen));
		printf("  Gateway ops : %d\n",ntohs(bootp->bp_hops));
		printf("  Transaction ID : %d\n",ntohs(bootp->bp_xid));
		printf("  Seconds since begging : %d\n",ntohs(bootp->bp_secs));

		printf("  Client Hard addr : ");
		readU_Char(bootp->bp_chaddr,sizeof(bootp->bp_chaddr),SMALL);
		printf("\n");

		printf("  Server host name : ");
		readU_Char(bootp->bp_sname,sizeof(bootp->bp_sname),SMALL);
		printf("%s\n",bootp->bp_sname);//,sizeof(bootp->bp_sname),SMALL);
		printf("\n");

		printf("  Boot file name : ");
		readU_Char(bootp->bp_file,sizeof(bootp->bp_file),SMALL);
		printf("%s\n",bootp->bp_file);
		printf("\n");
		
		printf("  Vendor spe : ");
		readU_Char(bootp->bp_vend,sizeof(bootp->bp_vend),SMALL);
		printf("%s\n",bootp->bp_vend);//(bootp->bp_vend,sizeof(bootp->bp_vend),SMALL);
		printf("\n");
		offset += sizeof(struct bootp*);
		readApplicatif("BootP",header,packet,offset,3);
	}
	else if(verbose == MID){
		printf("BOOTP : \n");
		switch(bootp->bp_op){
			case BOOTREQUEST:
				printf("Request \n");
				break;
			case BOOTREPLY:
				printf("Reply\n");
				break;
			default:
				break;
		}
	}
	else{
		printf("BOOTP \n");
	}
	exit(1);
}

void readUDP(const struct pcap_pkthdr * header, const u_char * packet,struct udphdr * udp, int offset,int verbose){
	if(verbose == 3){
		printf("UDP : \n");
		printf("  Source port : %d\n",udp->source );
		printf("  Destination port : %d\n",udp->dest );
		printf("  Length : %d\n",udp->len );
		printf("  Checksum : %d\n",udp->check );
	}
	else if(verbose == 2){
		printf("UDP : portdest -> %d , portsrc -> %d\n",udp->dest,udp->source);
	}
	else{
		printf("UDP, ");
	}
	switch(udp->source){
		case BOOTPC:
			readBootP(header,packet,offset,verbose);
			break;
		case BOOTPS:
			readBootP(header,packet,offset,verbose);
			break;
		case DNS1:
			readApplicatif("DNS",header,packet,offset,verbose);
			break;
		default:
			switch(udp->dest){
				case BOOTPS:
					readBootP(header,packet,offset,verbose);
					break;
				case BOOTPC:
					readBootP(header,packet,offset,verbose);
					break;
				case DNS2:
					readApplicatif("DNS",header,packet,offset,verbose);
					break;
				default:
					readApplicatif("Applicatif ",header,packet,offset,verbose);
					break;
			}
	}
}

//Lecture du segment TCP
void readTCP(const struct pcap_pkthdr * header, const u_char * packet,int offset,int verbose){
	struct tcphdr* tcp= (struct tcphdr*)(packet + offset); 
	if(verbose == HIG){
		printf("TCP : \n");	
		printf("  Port src : %d\n",ntohs(tcp->source));
		printf("  Port dest : %d\n",ntohs(tcp->dest));
		printf("  seq : %d\n",ntohs(tcp->seq));	
		printf("  ack_seq : %d\n",ntohs(tcp->ack_seq));
		printf("  Window : %d\n",ntohs(tcp->window));	
		printf("  Flags : %d\n",ntohs(tcp->res1));	
		printf("  Data Offset : %d\n",ntohs(tcp->doff));	
		printf("  Checksum : %d\n",ntohs(tcp->check));	
		printf("  Urgent pointer : %04x\n",(tcp->urg_ptr));	
	}
	else if(verbose == MID){
		printf("flag : %d\n",ntohs(tcp->res1));
		switch(tcp->res1){
			case TCP_SYN_SENT:
				printf("  SYN sent\n");
				break;
			case TCP_SYN_RECV:
				printf("  SYN recv\n");
				break;
			case TCP_FIN_WAIT1:
				printf("  FIN\n");
				break;
			case TCP_FIN_WAIT2:
				printf("  FIN\n");
				break;
			case TCP_TIME_WAIT:
				printf("  TIME WAIT\n");
				break;
			case TCP_CLOSE:
				printf("  CLOSE\n");
				break;
			case TCP_CLOSE_WAIT:
				printf("  CLOSE WAIT\n");
				break;
			case TCP_LAST_ACK:
				printf("  LAST_ACK\n");
				break;
			case TCP_LISTEN:
				printf("  LISTEN\n");
				break;
			case TCP_CLOSING:
				printf("  CLOSING\n");
				break;
			default:
				printf("  UNDEFINED\n");
				break;
		}
	}
	else{
		printf("TCP, ");
	}

	int sport =ntohs(tcp->source) ;
	int dport =ntohs(tcp->dest) ;
	offset += sizeof(*tcp);

	char * appli = "UNKNOW PROTOCOL";

	if(sport == HTTP || dport == HTTP)
		appli = "HTTP";
	else if(sport == HTTPS || dport == HTTPS)
		appli = "HTTPS";
	else if(sport == FTP_TRANS || dport == FTP_TRANS)
		appli = "FTP (transfer)";
	else if(sport == FTP_ETA || dport == FTP_ETA)
		appli = "FTP (etablished)";
	else if(sport == DNS || dport == DNS)
		appli = "DNS";	
	else if(sport == SMTP || dport == SMTP)
		appli = "SMTP";
	else if(sport == POP2|| dport == POP3)
		appli = "POP2";
	else if(sport == POP3|| dport == POP3)
		appli = "POP3";
	else if(sport == IMAP || dport == IMAP)
		appli = "IMAP (2 ou 4)";
	else if(sport == IMAPSSL || dport == IMAPSSL)
		appli = "IMAP (ssl)";
	else if(sport == SCTP || dport == SCTP)
		appli = "SCTP";
	
	if(verbose == 3 || verbose == 2){
		readApplicatif(appli,header,packet,offset,verbose);
	}
	else{
		printf("%s\n",appli);
	}
}

void readApplicatif(char * application,const struct pcap_pkthdr* header,const u_char * packet, int offset, int verbose){

	if(verbose == 3){
		printf("\033[1;34m");	
		printf("\n------------------------ DEBUT APPLICATIF ------------------\n");
		printf("\033[00m");
		printf("%s : \n",application);
		const u_char * toRead = (packet + offset);
		int i;
		char toPrint;
		for (i = 0; i < header->len - offset; ++i)
		{
			toPrint = toRead[i];
			if(!isprint(toPrint))
				toPrint = '.';
			printf("%c",toPrint);
		}
		printf("\033[1;34m");	
		printf("\n------------------------ FIN APPLICATIF ------------------");
		printf("\033[00m");
		printf("\n\n");
	}
	else{
		printf("%s\n",application );
	}
	
}

void getHour(const struct pcap_pkthdr* header,int verbose){
	struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];
	gettimeofday(&tv, NULL);
	nowtime = tv.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S",nowtm);
	snprintf(buf, sizeof buf, "%s.%06d", tmbuf, tv.tv_usec);
	
	if(verbose == 1)
		printf("%s\n",buf );
	else{
		printf("\033[31m");
		printf("Message reçu à %s\n",buf );
		printf("\033[00m");
	}
}

void getHeaderLength(const struct pcap_pkthdr* header,int verbose){
	if(verbose != 1)
		printf("Taille du packet : %d\n",header->len);
}