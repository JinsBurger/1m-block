#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <unordered_set>
#include <iostream>
#include "headers.h"

using namespace std;


//https://quat.tistory.com/entry/C-map-%EA%B3%BC-unorderedmap-%EA%B2%80%EC%83%89-%EC%86%8D%EB%8F%84-%EB%B9%84%EA%B5%90
unordered_set<string> blacklist_hosts;

uint32_t is_http_pkt(char *data, uint32_t data_len) {
	const char* http_methods[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

	for(int i=0; i < sizeof(http_methods) / sizeof(char*); i++) {
		if(data_len > strlen(http_methods[i]) && !strncasecmp(data, http_methods[i], strlen(http_methods[i]))) {		
			return 0;
		}		
	}
	return -1;
}

float timedifference_msec(struct timeval t0, struct timeval t1) {
    return (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
}

uint32_t check_blacklisted_host(char *data, uint32_t data_len) {
	char *line = strtok(data, "\r\n");
	const char* host_header = "HOST: ";
	char *host;
	struct timeval t0;
   	struct timeval t1;

	while(line != NULL) {
		if(!strncasecmp(line, host_header, strlen(host_header))) {
			host = line + strlen(host_header);
			
			gettimeofday(&t0, 0);
			if(blacklist_hosts.find(string(host)) != blacklist_hosts.end()) {
				gettimeofday(&t1, 0);
				printf("COMPARING TIME FOR %s: %f miliseconds \n", host, timedifference_msec(t0, t1));

				return 1;
			} else {
				return 0;
			}	
		}
		line = strtok(NULL, "\r\n");
	}
	return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void * data) {

	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *pkt; int pkt_len;
	struct libnet_ipv4_hdr *ipv4_hdr;
	struct libnet_tcp_hdr *tcp_hdr;
	char *payload; uint32_t payload_len;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) id = ntohl(ph->packet_id);
	else goto _accept;

	pkt_len = nfq_get_payload(nfa, &pkt);
	if (pkt_len < 0)
		goto _accept;

	/* Parsing TCP packet */
	ipv4_hdr = (struct libnet_ipv4_hdr*)pkt;
	if(ipv4_hdr->ip_p != IPPROTO_TCP)
		goto _accept;

	tcp_hdr = (struct libnet_tcp_hdr*)((char*)ipv4_hdr+(ipv4_hdr->ip_hl)*4);
	payload = (char*)tcp_hdr+(tcp_hdr->th_off*4);
	payload_len = pkt_len - ((unsigned char*)payload - pkt);
	
	if(is_http_pkt(payload, payload_len) == 0) {
		if(check_blacklisted_host(payload, payload_len))
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}

	_accept:
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void read_bloacklist(char *filename) {
	FILE *fp;
	int tmp;
	char host[0x300];
	struct timeval t0;
   	struct timeval t1;
   	float elapsed;

	if((fp = fopen(filename, "r")) == NULL) {
		perror("fopen");
		exit(-1);
	}

	
	gettimeofday(&t0, 0);
	while(1) {
		if(fscanf(fp, "%d,%s", &tmp, host) != 2)
			break;
		blacklist_hosts.insert(string(host));
	}
	gettimeofday(&t1, 0);

	printf("DIFF FOR LOADING BLACKLIST: %f milisecons \n", timedifference_msec(t0, t1));
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc < 2) {
		printf("usage: 1m-block <site list file>\n");
		exit(-1);
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	/* Insert blacklisted host which passed by argument */
	read_bloacklist(argv[1]);
	
	for (;;) {
		//printf("wait packets \n");
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

