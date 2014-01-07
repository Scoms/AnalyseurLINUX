#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "reader.h"
#include "analyseur.h"
#include <fcntl.h>

#define TRUE 1
#define FALSE 0
#define BUFFSIZE 1500
#define ARGNUM 2
#define SNAPLEN 1
#define PROMISC 0
#define TOMS 0
#define INFINITY -1


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
//Globals 
int verbose;

int main(int argc, char * argv[]){

	//déclarations de variables 
	char * device, * errbuff;
	const char * filtre = NULL;
	const char * file = NULL;
	int optch;
	pcap_t* listener;
	verbose = 3;

	// format de lecture des paramètres 
    char format[] = "i:v:f:o:";
    // device = "";
 
 	//boucle de lecture des parmètres
    while ((optch = getopt(argc, argv, format)) != -1)
    switch (optch) {
        case 'i':
			device = testDevice(optarg);
            break;
        case 'o':
        	file = optarg;
            break;
        case 'f':
            filtre = optarg;
            break;
        case 'v':
            verbose = atoi(optarg) <= 3 && atoi(optarg) >= 1 ? atoi(optarg) : 3;
            break;
    }
    //printf("fin du traitement %s %i \n",device,strcmp(device," "));
    //test de la validité du device spécifié

    if(device == NULL)
    	errorQuit("veuillez définir un interface ou un fichier : ./analyseur -i <interface> || ./analyseur -f <fichier>");   

    // LIVE MODE 
    if(file == NULL){
    	printf("--------- LIVE MODE ------------\n");
    	printf("Lecture sur : %s\n",device);
    	listener = pcap_open_live(device, BUFSIZ, 1, 1000, errbuff); 
		pcap_datalink(listener);
		//test et mise en place du filtre
	    if(filtre != NULL){
			printf("Application du filtre : %s\n",filtre);
			struct bpf_program fp;
			bpf_u_int32 netmask;
			int optimise;
			if(pcap_compile(listener, &fp, filtre, optimise,netmask) != 0){
				printf("Echec lors de la compilation du filtre\n");
			}
			else{
				if(pcap_setfilter(listener,&fp) != 0){
						printf("Echec lors de l'application du filtre\n");			
				}
				else{
					printf("Le filtre à été appliqué avec succès !\n");
				}
			}
		}
	    pcap_loop(listener, INFINITY, readPacket, NULL);		
    }

    // Lecture du fichier 
    else{
    	printf("Lecture de : %s\n",file);
    	int openres = open(file,O_RDONLY);
    	
    	// si le fichier nexiste pas 
    	if(openres == -1)
    		errorQuit("Le fichier demandé n'existe pas.");

    	listener = pcap_open_offline (file, errbuff);
		pcap_datalink(listener);
	    pcap_loop(listener, INFINITY, readPacket, NULL);		
    }
    pcap_close(listener);
	return 0;
}

void readPacket(u_char *args, const struct pcap_pkthdr* header, const u_char *packet){
	headerDisplay(header);
	packetDisplay(header,packet,verbose);
	printf("\n");
	//printf("\nexiste");
}


void headerDisplay(const struct pcap_pkthdr* header){
	getHour(header,verbose);
	getHeaderLength(header,verbose);
}

//On test si le device demander est OK 
char * testDevice(char * device){
	char errbuff[BUFFSIZE];
	char print_list[BUFFSIZE];
	char row[100];
	char * dev;
	pcap_if_t *alldevs, *d;
	int i = 0;
	int res = pcap_findalldevs(&alldevs,errbuff);

	while(1){
		bzero(print_list,BUFFSIZE);
	    for(d=alldevs; d; d=d->next)
	    {
	    	bzero(row,100);
	    	dev = d->name;
	    	strcpy(row,dev);
	    	strcat(row,"\n");
	    	if(strcmp(dev,device) == 0){
	    		return dev;
	    	}
	    	strcat(print_list,row);
	    }
		printf("%s%s :",print_list,"Choisir device");
		fscanf(stdin, "%s", device);
	}
}

void errorQuit(char * msg){
	printf("%s\n",msg);
	exit(0);
}