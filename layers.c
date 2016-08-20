#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <memory.h>
#include <time.h>

#include "layers.h"

const unsigned ipv4_header_min_size = 20;
const unsigned ipv4_header_max_size = 60;
const unsigned tcp_header_min_size = 20;
const unsigned tcp_header_max_size = 60;

unsigned short checksum(unsigned short *buf, int len) {
    unsigned long cksum = 0;

    while(len > 1) {
        cksum +=*buf++;
        len   -=sizeof(unsigned short);
    }

    if(len)
        cksum += *(unsigned char*)buf;

    cksum  = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}


void dump_bytes(uint8_t *buf, size_t bytes) {
	for(size_t i = 0; i < bytes; i++)
		printf("%02x ", *(buf+i));
	printf("\n");
}
 


void ipv4_init_(struct ipv4_header *h, Session *ctx, struct addrinfo *src, struct addrinfo *dst) {
	memset(h, 0, sizeof(struct ipv4_header));

	h->ver_ihl = 4 << 4 | 5 ; //Version 4, hdr size 5 32bit words
	h->ttl = 64;
	h->protocol = IPPROTO_TCP;

	h->sourceip = ((struct sockaddr_in*)src->ai_addr)->sin_addr.s_addr;
	h->destip = ((struct sockaddr_in*)dst->ai_addr)->sin_addr.s_addr;

}

void ipv4_init(struct ipv4_header *h, Session *ctx) {
	ipv4_init_(h, ctx, ctx->attacker_addr, ctx->daddr);
}


void ipv4_spoof_init(struct ipv4_header *h, Session *ctx) {
	ipv4_init_(h, ctx, ctx->saddr, ctx->daddr);
}

void ipv4_dump(struct ipv4_header *h) {
	printf("Ver: %u IHL: %u\n", h->ver_ihl >> 4, ipv4_get_ihl(h));
	printf("Len: %u TTL: %u Prot: %u\n", ipv4_get_len(h), h->ttl, ipv4_get_protocol(h));
}

struct tcp_header *ipv4_get_tcp(struct ipv4_header *h, uint32_t caplen) {
	uint32_t *ptr = (uint32_t *)h; //The ihl is expressed in 32bit words
	uint8_t ihl = ipv4_get_ihl(h);
	if (ihl < 5 ) {
		fprintf(stderr, "ipv4_get_tcp: ihl smaller than 5: %u\n", ihl);
		exit(EXIT_FAILURE);
	}

	if( (uint8_t *)(ptr+ihl)+ sizeof(struct tcp_header) >= (uint8_t *)(h)+caplen) {
		return NULL;
	}
 
	return  (struct tcp_header *)(ptr+ihl);
}

uint8_t ipv4_get_ihl(struct ipv4_header *h) {
	return h->ver_ihl & 15;
}

uint8_t ipv4_get_protocol(struct ipv4_header *h) {
	return h->protocol;
}

uint16_t ipv4_get_len(struct ipv4_header *h) {
	return ntohs(h->len);
}

void ipv4_set_dont_frag(struct ipv4_header *h) {
	h->frag_field |= 32768;
}



void tcp_init_(struct tcp_header *h, Session *ctx, struct addrinfo *src, struct addrinfo *dst) {
	memset(h, 0, sizeof(struct tcp_header));
	h->data_ns = 5 << 4; //default header size
	h->win = htons(ctx->window_size);

	h->srcport = ((struct sockaddr_in *)src->ai_addr)->sin_port;
	h->destport = ((struct sockaddr_in *)dst->ai_addr)->sin_port;

	h->seqnum = ctx->stream_seq + 1;
}

void tcp_init(struct tcp_header *h, Session *ctx) {
	tcp_init_(h, ctx, ctx->attacker_addr, ctx->daddr);
}

void tcp_spoof_init(struct tcp_header *h, Session *ctx) {
	tcp_init_(h, ctx, ctx->saddr, ctx->daddr);
}

void tcp_dump(struct tcp_header *h) {
	printf("Src. Port: %u Dst. Port: %u\n", ntohs(h->srcport), ntohs(h->destport));
	printf("Syn: %u Ack: %u Fin: %u Rst: %u\n", tcp_isset_syn(h), tcp_isset_ack(h), tcp_isset_fin(h), tcp_isset_rst(h));
	printf("Seq.: %u Acks.: %u\n", h->seqnum, h->acknum);
}

void tcp_calculate_checksum(struct ipv4_header *ip, struct tcp_header *h) {
	struct pseudo_header pseudo;
	memcpy(&pseudo.tcp, h, sizeof(struct tcp_header));
	pseudo.sourceip = ip->sourceip;
	pseudo.destip = ip->destip;
	pseudo.zero = 0;
	pseudo.protocol = 6;
	pseudo.tcp_len = htons(sizeof(struct tcp_header)); // + 0 Data
	h->chksum = checksum((uint16_t *)&pseudo, sizeof(struct pseudo_header));
}
void tcp_set_syn(struct tcp_header *h) {
	h->flags |= 2;
}

bool tcp_isset_syn(struct tcp_header *h) {
	return h->flags & 2;
}

void tcp_set_ack(struct tcp_header *h) {
	h->flags |= 16;
}

bool tcp_isset_ack(struct tcp_header *h) {
	return h->flags & 16;
}

void tcp_set_rst(struct tcp_header *h) {
	h->flags |= 4;
}

bool tcp_isset_rst(struct tcp_header *h) {
	return h->flags & 4;
}

void tcp_set_fin(struct tcp_header *h) {
	h->flags |= 1;
}

bool tcp_isset_fin(struct tcp_header *h) {
	return h->flags & 1;
}


void tcp_set_seqnum(struct tcp_header *h, uint32_t seq) {
	h->seqnum = htonl(seq);
}

uint32_t tcp_get_seqnum(struct tcp_header *h) {
	return ntohl(h->seqnum);
}

void tcp_set_acknum(struct tcp_header *h, uint32_t ack) {
	h->acknum = htonl(ack);
}

uint32_t tcp_get_acknum(struct tcp_header *h) {
	return ntohl(h->acknum);
}

void tcp_set_window_size(struct tcp_header *h, uint16_t size) {
	h->win = htons(size);
}

uint16_t tcp_get_window_size(struct tcp_header *h) {
	return ntohs(h->win);
}

void disable_ip_header(Session *ctx) {	
	int val = 1;
	if(setsockopt(ctx->raw_socket, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {
		perror("Setting IP_HDRINCL failed");
		exit(EXIT_FAILURE);
	}

}

void enable_ip_header(Session *ctx) {	
	int val = 0;
	if(setsockopt(ctx->raw_socket, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {
		perror("Unsetting IP_HDRINCL failed");
		exit(EXIT_FAILURE);
	}

}

Session *new_session(char *attacker_ip, int attacker_source_port,  char *source_ip,  char *destination_ip, int destination_port) {
	Session *ctx = (Session *)malloc(sizeof(Session));
	memset(ctx, 0, sizeof(Session));
	int ret;

	ctx->connection_closed = 0;
	ctx->nsec_offset = 0;
	ctx->stream_seq = 0;
	ctx->stream_acks = 0;

	if ((ret = getaddrinfo(attacker_ip, NULL, NULL, &ctx->attacker_addr)) != 0) {
		fprintf(stderr, "Source parsing failed: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	if ((ret = getaddrinfo(source_ip, NULL, NULL, &ctx->saddr)) != 0) {
		fprintf(stderr, "Source parsing failed: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}


	if ((ret = getaddrinfo(destination_ip, NULL, NULL, &ctx->daddr)) != 0) {
		fprintf(stderr, "Destination parsing failed: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	if (ctx->attacker_addr->ai_family != AF_INET ||
		ctx->daddr->ai_family         != AF_INET ||
		ctx->saddr->ai_family         != AF_INET   ) {

		fprintf(stderr, "Only ipv4 is supported, because someone couldn't be bothered\n");
		exit(EXIT_FAILURE);
	}

	((struct sockaddr_in *)ctx->attacker_addr->ai_addr)->sin_port = htons(attacker_source_port);
	((struct sockaddr_in *)ctx->daddr->ai_addr)->sin_port = htons(destination_port);

	session_connect(ctx);	

	return ctx;
}

void session_set_source_port(Session *ctx, uint16_t port) {
	((struct sockaddr_in *)ctx->saddr->ai_addr)->sin_port = htons(port);
}

void session_set_attacker_port(Session *ctx, uint16_t port) {
	((struct sockaddr_in *)ctx->attacker_addr->ai_addr)->sin_port = htons(port);
}

uint16_t session_get_source_port(Session *ctx) {
	return ntohs(((struct sockaddr_in *)ctx->saddr->ai_addr)->sin_port);
}

uint16_t session_get_destination_port(Session *ctx) {
	return ntohs(((struct sockaddr_in *)ctx->daddr->ai_addr)->sin_port);
}

uint16_t session_get_attacker_port(Session *ctx) {
	return ntohs(((struct sockaddr_in *)ctx->attacker_addr->ai_addr)->sin_port);
}



struct tcp_header *session_read_packet(Session *ctx) {
	struct tcp_header *h = (struct tcp_header*)malloc(tcp_header_max_size);
	struct pcap_pkthdr *header; 
	const u_char *packet;

	if (pcap_next_ex(ctx->handle, &header, &packet)) {
		struct ipv4_header *v4_h = (struct ipv4_header *)(packet + 16);
		struct tcp_header *unsafe_h = ipv4_get_tcp(v4_h, header->caplen-16);

		if(unsafe_h == NULL) {
			return NULL;
		}
	
		memcpy(h, unsafe_h, sizeof(struct tcp_header));
		return h;
	}

	return NULL;
}


void session_read_packets_update_1s(Session *ctx) {
	time_t start = time(NULL);

	while(time(NULL)-start <= 1) {
		struct tcp_header *h = session_read_packet(ctx);
		if (h == NULL)
			   continue;
		ctx->stream_seq = tcp_get_acknum(h);
		ctx->stream_acks = tcp_get_seqnum(h);
		free(h);
	}
}

void session_read_sin_ack(Session *ctx) {
	struct tcp_header *h = session_read_packet(ctx);

	if(h == NULL){
		printf("Didn't catch a single packet\n");
		exit(EXIT_FAILURE);
	}

	if (!tcp_isset_syn(h) && !tcp_isset_ack(h)){
		free(h);
		exit(EXIT_FAILURE);
	}

	ctx->stream_seq = tcp_get_acknum(h);
	ctx->stream_acks = tcp_get_seqnum(h);
	ctx->window_size = tcp_get_window_size(h);
	free(h);

}



void session_connect(Session *ctx) {
	char *dev = "any";
	char errbuf[PCAP_ERRBUF_SIZE];
 	bpf_u_int32 mask;
 	bpf_u_int32 net;
	struct bpf_program fp;
	char filter_exp[1024];
	char ip[256];
	snprintf(filter_exp, 1024,"src host %s and tcp dst port %i and tcp src port %i",
			inet_ntop(ctx->daddr->ai_family,
			(void *)&((struct sockaddr_in *)ctx->daddr->ai_addr)->sin_addr, ip, 256),
			session_get_attacker_port(ctx), session_get_destination_port(ctx));

	ctx->handle = pcap_open_live(dev, 1024, 1, 500, errbuf);
	if(ctx->handle == NULL ) {
		fprintf(stderr, "Couldn't open device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}


	/* Compile and apply the filter */
	if (pcap_compile(ctx->handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(ctx->handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
		exit(EXIT_FAILURE);
	}

	ctx->raw_socket = socket(ctx->attacker_addr->ai_family , SOCK_RAW, IPPROTO_TCP);
	if(ctx->raw_socket < 0) {
		perror("Socket creation failed");
	}

	ctx->stream_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(bind(ctx->stream_socket, ctx->attacker_addr->ai_addr, ctx->daddr->ai_addrlen) == -1) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

	if(connect(ctx->stream_socket, ctx->daddr->ai_addr, ctx->daddr->ai_addrlen) == -1 ) {
		perror("Connect failed");
		exit(EXIT_FAILURE);
	}

	disable_ip_header(ctx);
	ctx->connection_closed = 0;
	session_read_sin_ack(ctx);
	session_read_packets_update_1s(ctx);
}


void session_reconnect_increase(Session *ctx) {
printf("[!] Sidechannel socket lost, reconnecting.\n");
	int tmp = ctx->window_size;
	pcap_close(ctx->handle);
	close(ctx->raw_socket);
	close(ctx->stream_socket);
	session_set_attacker_port(ctx, session_get_attacker_port(ctx)+1);
	session_connect(ctx);
	//This is a bit crude
	ctx->window_size = tmp;
}
