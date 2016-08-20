#ifndef __LAYERS_H__
#define __LAYERS_H__

#include <stdint.h>
#include <stdbool.h>
#include <pcap.h>

typedef struct {
	pcap_t *handle;
	int              raw_socket;
	int              stream_socket;
	struct addrinfo *attacker_addr;
	struct addrinfo *saddr;
	struct addrinfo *daddr;


	uint32_t stream_seq;
	uint32_t stream_acks;

	int connection_closed;

	long nsec_offset;
	uint32_t sequence_chunk_start;
	uint32_t sequence_chunk_end;
	uint32_t step;
	int sequence_i;
	uint32_t sequence_in_window;
	uint16_t window_size;

} Session;


#pragma pack(1)
struct ipv4_header {
	uint8_t      ver_ihl;
	uint8_t      dscp_ecn; //formerly tos
	uint16_t     len;
	uint16_t     ident;
	uint16_t     frag_field;
	uint8_t      ttl;
	uint8_t      protocol;
	uint16_t     chksum;
	uint32_t     sourceip;
	uint32_t     destip;
};

extern const unsigned ipv4_header_min_size;
extern const unsigned ipv4_header_max_size;


#pragma pack(1)
struct tcp_header {
	uint16_t  srcport;
	uint16_t  destport;
	uint32_t  seqnum;
	uint32_t  acknum;
	uint8_t   data_ns;
	uint8_t   flags;
	uint16_t  win;
	uint16_t  chksum;
	uint16_t  urgptr;
};


#pragma pack(1)
struct pseudo_header {
	uint32_t     sourceip;
	uint32_t     destip;
	uint8_t 	 zero;
	uint8_t		 protocol;
	uint16_t 	 tcp_len;
	struct tcp_header tcp;
};

extern const unsigned tcp_header_min_size;
extern const unsigned tcp_header_max_size;

void ipv4_init(struct ipv4_header *h, Session *ctx);
void ipv4_spoof_init(struct ipv4_header *h, Session *ctx);
void ipv4_dump(struct ipv4_header *h);
void ipv4_set_dont_frag(struct ipv4_header *h);
uint8_t ipv4_get_ihl(struct ipv4_header *h);
uint8_t ipv4_get_protocol(struct ipv4_header *h);
uint16_t ipv4_get_len(struct ipv4_header *h);
struct tcp_header *ipv4_get_tcp(struct ipv4_header *h, uint32_t caplen);

void tcp_init(struct tcp_header *h, Session *ctx);
void tcp_spoof_init(struct tcp_header *h, Session *ctx);
void tcp_dump(struct tcp_header *h);
void tcp_calculate_checksum(struct ipv4_header *ip, struct tcp_header *h);


void tcp_set_syn(struct tcp_header *h);
void tcp_set_ack(struct tcp_header *h);
void tcp_set_rst(struct tcp_header *h);
void tcp_set_fin(struct tcp_header *h);

bool tcp_isset_syn(struct tcp_header *h);
bool tcp_isset_ack(struct tcp_header *h);
bool tcp_isset_rst(struct tcp_header *h);
bool tcp_isset_fin(struct tcp_header *h);

void tcp_set_seqnum(struct tcp_header *h, uint32_t seq); 
uint32_t tcp_get_seqnum(struct tcp_header *h);
void tcp_set_acknum(struct tcp_header *h, uint32_t ack);
uint32_t tcp_get_acknum(struct tcp_header *h);
void tcp_set_window_size(struct tcp_header *h, uint16_t size);
uint16_t tcp_get_window_size(struct tcp_header *h);

void disable_ip_header(Session *ctx);
void enable_ip_header(Session *ctx);
Session *new_session(char *attacker_ip, int attacker_source_port,  char *source_ip,  char *destination_ip, int destination_port);
void session_connect(Session *ctx);
struct tcp_header *session_read_packet(Session *ctx);
void session_set_source_port(Session *ctx, uint16_t port);
uint16_t session_get_source_port(Session *ctx);

void session_reconnect_increase(Session *ctx);
#endif 
