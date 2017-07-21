#include <pcap.h>
#include <stdio.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
	 int main(int argc, char *argv[])
	 {
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */		
		 int ptype;//type 
		const u_char *packet;		/* The actual packet */
		char buf[20];
		struct ip *iph;//ip struct
		struct tcphdr *tcph;//tcp struct
		struct ether_header *pEth;//ethernet struct
		#define IP_HEADER 0x0800
		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab a packet */
		while(1){
		
			int ren=(int)pcap_next_ex(handle,&header,&packet);
			if(ren==0)continue;
			else if(ren<0)break;
		
			pEth=(struct ether_header *)packet;
			ptype=ntohs(pEth->ether_type);
			iph=(struct ip *)(packet+sizeof(*pEth));
			
			printf("****************MAC ADDRESS****************");	
			printf("\nDst MAC Address: ");
			for(int i=0;i<6;i++){
					printf("%02x:",pEth->ether_dhost[i]);
			}
			printf("\nSrc MAC Address : ");
			for(int i=0;i<6;i++){				
				printf("%02x:",pEth->ether_shost[i]);
			}			
			printf("\n");
			if(ptype==ETHERTYPE_IP){
                  	      printf("\nUpper protocal is IP HEADER(%04x)\n",ptype);
				if (iph->ip_p == IPPROTO_TCP)
       				{
           				tcph = (struct tcphdr *)(packet+sizeof(*pEth)+((iph->ip_hl) * 4));
					printf("****************ip address****************\n");
					inet_ntop(AF_INET,&(iph->ip_src),buf,sizeof(buf));
					printf("Src Address : %s\n", buf);
					inet_ntop(AF_INET,&(iph->ip_dst),buf,sizeof(buf));
      	 				printf("Dst Address : %s\n", buf);
					printf("\n****************TCP address****************\n");
					printf("Src Port    : %d\n" , ntohs(tcph->source));
           				printf("Dst Port    : %d\n" , ntohs(tcph->dest));
				/* Print its length */
					printf("Jacked a packet with length of [%d]\n", header->len);
					
					int k=0;
					for(int i=sizeof(pEth)+sizeof(iph)+sizeof(tcph); i < header->len; i++){
						if (k %16 ==0)
							fprintf(stdout,"\n");
						else
							fprintf(stdout, "%02X ",*(packet + i));
						k++;				
					}
      				}
                
				
				printf("\n\n\n\n");
			}	
		/* And close the session */
		
		}
	pcap_close(handle);
	return 0;
	}
