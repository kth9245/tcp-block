#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <time.h> 
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#pragma pack(push, 1)

typedef struct {
	u_int8_t  ether_dhost[6];
	u_int8_t  ether_shost[6];
	u_int16_t ether_type;  
} libnet_ethernet_hdr;

typedef struct {
    u_int8_t ip_hl:4,
           ip_v:4;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    u_int32_t ip_src;
    u_int32_t ip_dst;
} libnet_ipv4_hdr;

typedef struct {
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t off;
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
} libnet_tcp_hdr;

typedef struct{
    u_int32_t src;
    u_int32_t dst;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t tcp_length;
}pseudo_hdr;

typedef struct{
	EthHdr eth;
	libnet_ipv4_hdr ip;
	libnet_tcp_hdr tcp;
}tcp_packet;

#pragma pack(pop)

char my_mac[18];

void usage() {
	printf("syntax: ./tcp-block <interface> <pattern>\n");
	printf("sample: ./tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

uint16_t checksum(void* packet, int len) {
	uint16_t *buf = (uint16_t*)packet;
    uint32_t sum = 0;
    uint16_t result;
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(uint8_t*)packet;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = (uint16_t)~sum;
    return result;
}


void send_rst(tcp_packet* origin, pcap_t* handle){
	int ethlen = 14;
	int iplen = 4*origin->ip.ip_hl;
	int tcplen = 4*(origin->tcp.off >> 4);
	tcp_packet* rst_packet = (tcp_packet*)malloc(ethlen + iplen + tcplen);
	memcpy(rst_packet, origin, ethlen + iplen + tcplen);

	rst_packet->eth.smac_ = Mac(my_mac);
	rst_packet->eth.dmac_ = origin->eth.dmac_;

	rst_packet->ip.ip_len = htons(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr));
	rst_packet->ip.ip_sum = 0;
	rst_packet->ip.ip_sum = (checksum((unsigned char*)(rst_packet)+ ethlen, iplen));

	rst_packet->tcp.th_dport = origin->tcp.th_dport;
	rst_packet->tcp.th_sport = origin->tcp.th_sport;
	rst_packet->tcp.th_seq = htonl(ntohl(origin->tcp.th_seq) + ntohs(origin->ip.ip_len) - iplen - tcplen);
	rst_packet->tcp.th_ack = origin->tcp.th_ack;
	rst_packet->tcp.off = (sizeof(libnet_tcp_hdr) / 4) << 4;
	rst_packet->tcp.th_flags = 0x14;
	rst_packet->tcp.th_win = 0;
	rst_packet->tcp.th_sum = 0;
	rst_packet->tcp.th_urp = 0;

	pseudo_hdr psh;
	psh.src = (rst_packet->ip.ip_src);
    psh.dst = (rst_packet->ip.ip_dst);
    psh.zero = 0;
    psh.protocol = 6;
    psh.tcp_length = htons(sizeof(libnet_tcp_hdr));
	unsigned char *pseudo = (unsigned char*)malloc(sizeof(pseudo_hdr) + sizeof(libnet_tcp_hdr));

	memcpy(pseudo, &psh, sizeof(pseudo_hdr));
    memcpy(pseudo + sizeof(pseudo_hdr), (unsigned char*)(rst_packet) + ethlen + iplen, sizeof(libnet_tcp_hdr));

    rst_packet->tcp.th_sum = checksum((unsigned char*)pseudo, sizeof(pseudo_hdr) + sizeof(libnet_tcp_hdr));
	int res = pcap_sendpacket(handle, (u_char*)rst_packet, sizeof(EthHdr) + ntohs(rst_packet->ip.ip_len));
	if (res == -1) fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
	
	free(pseudo);
	free(rst_packet);
}

void send_warning(tcp_packet* origin, pcap_t* handle){
	int ethlen = 14;
	int iplen = 4*origin->ip.ip_hl;
	int tcplen = 4*(origin->tcp.off >> 4);
	const char warning[] = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
	tcp_packet* warn_packet = (tcp_packet*)malloc(ethlen + iplen + tcplen + strlen(warning));
	memcpy(warn_packet, origin, ethlen + iplen + tcplen);
	memcpy((unsigned char*)(warn_packet)+ sizeof(tcp_packet), warning, strlen(warning));

	warn_packet->eth.smac_ = Mac(my_mac);
	warn_packet->eth.dmac_ = origin->eth.smac_;

	warn_packet->ip.ip_src = origin->ip.ip_dst;
	warn_packet->ip.ip_dst = origin->ip.ip_src;
	warn_packet->ip.ip_ttl = 128;
	warn_packet->ip.ip_len = htons(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr) + strlen(warning));
	warn_packet->ip.ip_sum = 0;
	warn_packet->ip.ip_sum = checksum((unsigned char*)(warn_packet)+ ethlen, iplen);

	warn_packet->tcp.th_dport = origin->tcp.th_sport;
	warn_packet->tcp.th_sport = origin->tcp.th_dport;
	warn_packet->tcp.th_seq = origin->tcp.th_ack;
	warn_packet->tcp.th_ack = htonl(ntohl(origin->tcp.th_seq) + ntohs(origin->ip.ip_len) - iplen - tcplen);
	warn_packet->tcp.off = (sizeof(libnet_tcp_hdr) / 4) << 4;
	warn_packet->tcp.th_flags = 0x19;
	warn_packet->tcp.th_sum = 0;
	warn_packet->tcp.th_win = 0;
	warn_packet->tcp.th_urp = 0;

	pseudo_hdr psh;
	psh.src = warn_packet->ip.ip_dst;
    psh.dst = warn_packet->ip.ip_src;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(libnet_tcp_hdr) + strlen(warning));
	int psize = sizeof(pseudo_hdr) + sizeof(libnet_tcp_hdr) + strlen(warning);
	unsigned char *pseudo = (unsigned char*)calloc(1, psize);
	memcpy(pseudo, (char *)&psh, sizeof(pseudo_hdr));
    memcpy(pseudo + sizeof(pseudo_hdr), &(warn_packet->tcp), sizeof(libnet_tcp_hdr) + strlen(warning));
	
    warn_packet->tcp.th_sum = (checksum((unsigned char*)pseudo, psize));

	//int res = pcap_sendpacket(handle, (u_char*)warn_packet, sizeof(EthHdr) + ntohs(warn_packet->ip.ip_len));
	//if (res == -1) fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
	
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
    sin.sin_port = warn_packet->tcp.th_sport;
    sin.sin_addr.s_addr = warn_packet->ip.ip_src;
	if (sendto(sock, (unsigned char*)warn_packet + ethlen, ntohs(warn_packet->ip.ip_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
		perror("sendto failed");
	}

	free(pseudo);
	free(warn_packet);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}
	struct ifreq ifr;
	char* dev = argv[1];
	char* pattern = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	for (int i = 0; i < 6; ++i) {
		sprintf(&my_mac[i*3], "%02X:", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
	}
	my_mac[17] = '\0'; 

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
				printf("couldn't open device %s(%s)\n", dev, errbuf);
	}		
	struct pcap_pkthdr* header;
	const u_char* packet;
	while (true) {
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*)packet;
		if(ntohs(eth_hdr->ether_type) != 0x0800) continue;
		libnet_ipv4_hdr* ip_hdr = (libnet_ipv4_hdr*)(packet + 14);
		if(ip_hdr->ip_p != 0x06) continue;
		libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)(packet + 14 + 4*ip_hdr->ip_hl);
		int data_len = header->caplen - 14 - 4*ip_hdr->ip_hl - 4*(tcp_hdr->off>>4);
		if(data_len > strlen(pattern)){
			char *data = (char *)(packet + (header->caplen - data_len));
			for(int i = 0; i < data_len - strlen(pattern); i++ ){
				if (strncmp(data+i, pattern, strlen(pattern)) == 0){
					tcp_packet* origin = (tcp_packet*)packet;
					printf("Detect\n");
					send_rst(origin, handle);
					send_warning(origin, handle);
					printf("Send Packet\n");
					sleep(10);
				}
			}
		}
	}
	pcap_close(handle);
}
