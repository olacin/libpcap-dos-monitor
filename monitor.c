/*
 ****************************************
 *
 * TCP SYN & DNS traffic monitoring program
 *
 ****************************************/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

pcap_t * descr;
char *device;

/* Ethernet header size */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* UDP protocol header. */
struct sniff_udp {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_ulen;                /* udp length */
        u_short uh_sum;                 /* udp checksum */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


void processPacket(u_char *useless,const struct pcap_pkthdr *header,const u_char* packet) {
	static int allpackets = 0;
	static int monitoredpackets = 0;
	allpackets++;

    	const struct sniff_ethernet *ethernet;  /* ethernet header */
	const struct sniff_ip *ip;              /* IP header */
	const struct sniff_tcp *tcp;            /* TCP header */
	const struct sniff_udp *udp;		/* UDP header */

	int size_ip;
	int size_tcp;
	int size_udp;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	char* protocol = "";
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			protocol = "TCP";
			/* define/compute TCP header offset */
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			/* Check if TCP SYN packet */
			if (tcp->th_flags & TH_SYN) {
				monitoredpackets++;
        			/* print source and destination IP addresses */
				printf("%s:%d -> ", 
				inet_ntoa(ip->ip_src),
				ntohs(tcp->th_sport));
				printf("%s:%d - %s (SYN) | %d monitored / %d total packets\n",
				inet_ntoa(ip->ip_dst),
				ntohs(tcp->th_dport),
				protocol,
				monitoredpackets,
				allpackets);
    		}
			break;
		case IPPROTO_UDP:
			protocol = "UDP";
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			if (ntohs(udp->uh_dport) == 53) {
				monitoredpackets++;
        			/* print source and destination IP addresses */
				printf("%s:%d -> ", 
				inet_ntoa(ip->ip_src),
				ntohs(udp->uh_sport));
				printf("%s:%d - %s (DNS) | %d monitored / %d total packets\n",
				inet_ntoa(ip->ip_dst),
				ntohs(udp->uh_dport),
				protocol,
				monitoredpackets,
				allpackets);
			}
			break;
		default:
			protocol = "Unknown protocol";
			break;
	}
}

int main(int argc, char *argv[]) {
	if(argc != 2) {
		printf("Usage : %s <network interface>\n",argv[0]);
		return 1;
	} else {
	device = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];  // if failed, contains the error text
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);  // errbuf initialized
        
	// Open device in promiscuous mode
	descr=pcap_open_live(device, BUFSIZ, 1, 512, errbuf);

	// Start infinite packet processing loop
	pcap_loop(descr, -1, processPacket, (u_char *) NULL);

	// Close the descriptor of the opened device
	pcap_close(descr);

	return 0;
	}
}
