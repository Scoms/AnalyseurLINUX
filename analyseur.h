
//Prototypes 
void errorQuit(char * msg);
char * testDevice(char * device);
void readPacket(u_char *args, const struct pcap_pkthdr*header, const u_char *packet);
void headerDisplay(const struct pcap_pkthdr* header);