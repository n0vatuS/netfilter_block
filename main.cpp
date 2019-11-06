#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define HW_ADDR_LEN 	6
#define IP_ADDR_LEN 	4
#define TYPE_IPV4  0x0800
#define PTC_TCP    		6

typedef struct eth_hdr {
    uint8_t dst_addr[HW_ADDR_LEN];
    uint8_t src_addr[HW_ADDR_LEN];
    uint16_t eth_type;
} ETHER;

typedef struct ip_hdr {
	uint8_t iph_ihl:4, ip_ver:4;
	uint8_t iph_tos;
	uint16_t iph_len;
	uint16_t iph_ident;
	uint8_t iph_flags;
	uint16_t iph_offset;
	uint8_t iph_ttl;
	uint8_t iph_protocol;
	uint16_t iph_chksum;
    uint8_t iph_source[IP_ADDR_LEN], iph_dest[IP_ADDR_LEN];
} IP;

typedef struct tcp_hdr {
	uint16_t tcph_srcport;
	uint16_t tcph_destport;
	uint32_t tcph_seqnum;
	uint32_t tcph_acknum;
	uint8_t tcph_reserved:4, tcph_offset:4;
	uint8_t tcph_flags;
	uint16_t tcph_win;
	uint16_t tcph_chksum;
	uint16_t tcph_urgptr;
} TCP;

typedef struct header {
	ETHER eth_hdr;
	IP ip_hdr;
	TCP tcp_hdr;
};

char * host_name;

void usage(){
  printf("syntax : netfilter_block <host>\n");
  printf("sample : netfilter_block test.gilgil.net\n");
  exit(1);
}

bool compare_method(unsigned char * packet) {
	const char * method[6] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
	for(int i = 0; i < 6; i++) {
		if(strstr((char *)packet, method[i]) == (char *)packet && packet[strlen(method[i])] == 0x20)
            return true;
	}
	return false;
}

bool check_host(unsigned char * packet) {
	const char * str = "Host: ";
	char * host = strstr((char *)packet, str);
    if(host == NULL)
        return false;
    if(strstr((char *)host, host_name) == host+strlen(str) && host[strlen(host_name)+strlen(str)] == 0x0d)
        return true;
    return false;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");

	unsigned char * packet;
	int ret = nfq_get_payload(nfa, &packet);
	if(ret < 0) {
		struct header * header = packet;
		int tcp_len = 20 + header->ip_hdr.iph_ihl << 2 + header->tcp_hdr.tcph_reserved << 2;
		if(ntohs(header->eth_hdr.eth_type) == TYPE_IPV4 && 
			header->ip_hdr.iph_protocol == PTC_TCP && 
			header->ip_hdr.iph_len - tcp_len > 0 &&
			compare_method(packet + tcp_len) &&
			check_host(packet + tcp_len)) {
			printf("packet blocked...\n");
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc != 2) {
		usage();
	}

	host_name = argv[1];

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

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
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
