#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "avltree.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

int isBlock;
node * root;

void sig_handler(int signo); 					// 마지막 종료 함수 ctlr-C 로 종료

void blocking(unsigned char* buf, int size) {
	const char *GET = "GET ";
	const char *POST = "POST ";
	const char *HEAD = "HEAD ";
	const char *PUT = "PUT ";
	const char *DELETE = "DELETE ";
	const char *OPTIONS = "OPTIONS ";
	const char *Host = "Host: ";
	node * target = NULL;
	int i, IP_hdr_len, TCP_hdr_len;
	uint8_t tmp = 0x40;
	tmp = tmp ^ buf[0];
	IP_hdr_len = tmp*4;
	tmp = buf[IP_hdr_len+12]>>4;
	TCP_hdr_len = tmp*4;
	
	if(size > IP_hdr_len + TCP_hdr_len) {
		buf += IP_hdr_len + TCP_hdr_len;
		if( memcmp(buf, GET, 4) == 0 || memcmp(buf, PUT, 4) == 0 || memcmp(buf, POST, 5) == 0 || 
		memcmp(buf, HEAD, 5) == 0 || memcmp(buf, DELETE, 7) == 0 || memcmp(buf, OPTIONS, 8) == 0 ) {
			char *ptr = strstr((char *)buf, Host);
			if(ptr == NULL) return;
			for (i=0; i< size - IP_hdr_len - TCP_hdr_len -1; i++){
				if(ptr[i] == 0x0d && ptr[i+1] == 0x0a)
					break;
			}
			ptr[i] = '\0';
			ptr += strlen(Host);
				
			target = find(ptr, root);		// find in avl tree
			if(target) {
				isBlock = 1;
				printf("\n--------Blocking!!! : %s--------\n", ptr);
			}
		}
	}

	return;
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
	{	
		printf("payload_len=%d ", ret);
		blocking(data, ret);
	}

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	isBlock = 0;
	u_int32_t id = print_pkt(nfa);
	printf("entering callback!!!\n");
	if(isBlock) 
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void sig_handler(int signo)  					// 마지막메모리 정리를 위한 signal 핸들러 함수
{
    	printf("\n--------process stop!!!--------\n");
    	dispose(root);
	system("iptables -F");						// iptable 정리
    	printf("--------program finish success!!!--------\n");
    	
    	exit(0);
}

int main(int argc, char **argv)
{
	signal(SIGINT, sig_handler);   					 //시그널 핸들러 함수

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
    	int i=0, j=0;
    	const int max = 1000;
    	root = NULL;

    	FILE *fp;
    	char s[81];
    	fp = fopen("top-1m.csv", "r"); 						// 파일 열기

    	while(!feof(fp)){  							// 파일의 끝이 아니라면
//    	while(i++ != max){
	        j=0;
        	fgets(s, 80, fp);  						// 최대 80칸짜리 한줄 읽기
        	s[strlen(s)-1] = '\0';
	        while(s[j++] != ',');

//        	printf("%s\n", &s[j]);  					// 한줄 출력

        	root = insert( &s[j], root);
    	}

    	fclose(fp);

	system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");			// NFQ 설정
	
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

 
