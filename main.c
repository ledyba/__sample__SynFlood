#include <features.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <asm/types.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arcnet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <ctype.h>


#define INTERFACE "eth0"

static struct sockaddr peeraddr = 
						//{ARPHRD_ETHER,{0x00, 0x1B, 0x8B, 0x35, 0xCE, 0xA8}};
						  {ARPHRD_ETHER,{0x00, 0x90, 0xcc, 0xe7, 0x25, 0x02}};
#define TARGET_IP (0xc0a80103)//(0xc0a83265)
#define TARGET_PORT (23501)

static int sock_pd = 0;
static struct sockaddr myaddr;
static int interface_index;

//表示用関数群

void
print_ethaddr(p)
	const u_char *p;
{
	int i;
	struct ethhdr *eh;

	eh = (struct ethhdr *)p;

	for (i = 0; i < 5; ++i) 
		printf("%02x:", (int)eh->h_source[i]);
	printf("%02x -> ", (int)eh->h_source[i]);

	for (i = 0; i < 5; ++i) 
		printf("%02x:", (int)eh->h_dest[i]);
	printf("%02x", (int)eh->h_dest[i]);
	printf("\n");
}

void hexdump(unsigned char *p, int count)
{
	int i, j;

	for(i = 0; i < count; i += 16) {
		printf("%04x : ", i);
		for (j = 0; j < 16 && i + j < count; j++)
			printf("%2.2x ", p[i + j]);
		for (; j < 16; j++) {
			printf("   ");
		}
		printf(": ");
		for (j = 0; j < 16 && i + j < count; j++) {
			char c = toascii(p[i + j]);
			printf("%c", isalnum(c) ? c : '.');
		}
		printf("\n");
	}
}

//ソケット準備関数群

void prepare_sock(){
	struct ifreq ifr;
	int i;
	char buf[8192];
	struct sockaddr_ll sll;

	//よーわからんけど、ソケットを準備だ！
	sock_pd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock_pd < 0){
		puts("Failed to open socket file descripter.");
		exit(-1);
	}

	//インターフェースインデックスを取得
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	ioctl(sock_pd, SIOCGIFINDEX, &ifr);
	interface_index = ifr.ifr_ifindex;

	//自分のアドレスを取得
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(sock_pd, SIOCGIFHWADDR, &ifr) == -1) {
		puts("Failed to get My hardware addr.");
		exit(-1);
	}
	myaddr = ifr.ifr_hwaddr;

	//プロ…なんとかモード化
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	ioctl(sock_pd,SIOCGIFFLAGS,&ifr);
	ifr.ifr_flags|=IFF_PROMISC;
	ioctl(sock_pd,SIOCSIFFLAGS,&ifr);

	//bindしちゃう！
	memset(&sll, 0xff, sizeof(sll));
	sll.sll_family = AF_PACKET;	/* allways AF_PACKET */
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = interface_index;
	bind(sock_pd, (struct sockaddr *)&sll, sizeof(sll));

	//受信済みデータを消去
	do {
		fd_set fds;
		struct timeval t;
		FD_ZERO(&fds);	
		FD_SET(sock_pd, &fds);
		memset(&t, 0, sizeof(t));
		i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
		if (i > 0){
			recv(sock_pd, buf, i, 0);
		}
	} while (i);
}

void exit_sock(){
	//ファイルデスクリプタをクローズ
	if(close(sock_pd) < 0){
		puts("Failed to close socket file descripter.");
		exit(-1);
	}
}

//送受信用

unsigned short calc_checksum(unsigned short *buf, int size)
{
	unsigned long sum = 0;

	while (size > 1) {
		sum += *buf++;
		size -= 2;
	}
	if (size)
		sum += *(u_int8_t *)buf;

	sum  = (sum & 0xffff) + (sum >> 16);	/* add overflow counts */
	sum  = (sum & 0xffff) + (sum >> 16);	/* once again */
	
	return ~sum;
}

int build_syn_packet(char* buf){
	int c = 0;
	int checksum_idx;
	short* ip_header;
	char* tcp_header;
	char* ip_src;
	char* ip_dst;
	short checksum;
	//for TCP
	char tcp_buf[40];
	int b = 0;
	if(ARPHRD_ETHER == myaddr.sa_family){
		memcpy(buf + c, peeraddr.sa_data, ETH_ALEN);
		c += ETH_ALEN;
		memcpy(buf + c, myaddr.sa_data, ETH_ALEN);
		c += ETH_ALEN;
	}else{//未対応
		return -1;
	}
	//タイプを設定(IP)
	buf[c++] = 0x08;
	buf[c++] = 0x00;
	//IPヘッダ
		ip_header = (short*)&buf[c];
		buf[c++] = 0x45;//バージョン
		buf[c++] = 0x00;//Differentiated Services Field: 0x00 (DSCP 0x00: Default; ECN: 0x00)
		//TotalLength
		buf[c++] = 0x00;
		buf[c++] = 0x30;
		//識別子
		buf[c++] = (rand() >> 16) & 0xff;
		buf[c++] = (rand() >> 16) & 0xff;

		buf[c++] = 0x40;//Flags
		buf[c++] = 0x00;//Fragment offset: 0

		buf[c++] = 0x80;//TimeToLive

		buf[c++] = 0x06;//ptorocol: TCP

		//check_sum
		checksum_idx = c;
		buf[c++] = 0x00;
		buf[c++] = 0x00;
		
		//source addr
		ip_src = &buf[c];
		//buf[c++] = (rand() >> 16) & 0xff;
		//buf[c++] = (rand() >> 16) & 0xff;
		buf[c++] = 192;
		buf[c++] = 168;
		buf[c++] = (rand() >> 16) & 0xff;
		buf[c++] = (rand() >> 16) & 0xff;
		//buf[c++] = 192;
		//buf[c++] = 168;
		//buf[c++] = 1;
		//buf[c++] = 251;

		//dist. addr
		ip_dst = &buf[c];
		buf[c++] = (TARGET_IP >> 24) & 0xff;
		buf[c++] = (TARGET_IP >> 16) & 0xff;
		buf[c++] = (TARGET_IP >>  8) & 0xff;
		buf[c++] = (TARGET_IP >>  0) & 0xff;

		//calc.checksum
		checksum = calc_checksum(ip_header,20);
		buf[checksum_idx  ] = (checksum >> 8) & 0xff;
		buf[checksum_idx+1] = (checksum >> 0) & 0xff;

	//TCPヘッダ
		tcp_header = &buf[c];
		//source port
		buf[c++] = (rand() >> 16) & 0xff;
		buf[c++] = (rand() >> 16) & 0xff;

		//dist. port
		buf[c++] = (TARGET_PORT >>  8) & 0xff;
		buf[c++] = (TARGET_PORT >>  0) & 0xff;

		//シーケンスナンバー
		buf[c++] = (rand() >> 16) & 0xff;
		buf[c++] = (rand() >> 16) & 0xff;
		buf[c++] = (rand() >> 16) & 0xff;
		buf[c++] = (rand() >> 16) & 0xff;

		//応答番号(synなので、0)
		buf[c++] = 0x00;
		buf[c++] = 0x00;
		buf[c++] = 0x00;
		buf[c++] = 0x00;

		
		buf[c++] = 0x70;//ヘッダ長さ
		buf[c++] = 0x02;//モード：syn

		//window size
		buf[c++] = 0xff;
		buf[c++] = 0xff;

		//checksum
		checksum_idx = c;
		buf[c++] = 0x00;
		buf[c++] = 0x00;

		//緊急ポインタ
		buf[c++] = 0x00;
		buf[c++] = 0x00;

		//options
		buf[c++] = 0x02;
		buf[c++] = 0x04;
		buf[c++] = 0x05;
		buf[c++] = 0xb4;
		buf[c++] = 0x01;
		buf[c++] = 0x01;
		buf[c++] = 0x04;
		buf[c++] = 0x02;

		//calc.checksum
		memcpy(&tcp_buf[b],ip_src,4);
		b+=4;
		memcpy(&tcp_buf[b],ip_dst,4);
		b+=4;
		tcp_buf[b++] = 0x00;
		tcp_buf[b++] = 0x06;

		tcp_buf[b++] = 0x00;
		tcp_buf[b++] = 28;

		memcpy(&tcp_buf[b],tcp_header,28);
		checksum = calc_checksum((short*)tcp_buf,40);
		buf[checksum_idx  ] = (checksum >> 8) & 0xff;
		buf[checksum_idx+1] = (checksum >> 0) & 0xff;

	return c;
}

void send_syn(){
	struct sockaddr_ll sll;
	char buf[1024];
	FILE* tmp;
	//パケットの準備
	int c = build_syn_packet(buf);
	if(c < 0){
		puts("Failed to make packet.");
		return;
	}
	/*
	print_ethaddr(buf);
	hexdump(buf, c);
	tmp = fopen("synf.dat","wb");
	fwrite(buf,c,1,tmp);
	fclose(tmp);
	*/

	//いよいよ送信です。
	memset(&sll, 0, sizeof(sll));
	sll.sll_ifindex = interface_index;
	if(sendto(sock_pd, buf, c, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0){
		puts("Failed to send packet.");
	}
}

void receive(){
	int i;
	char buf[8192];
	//受信！
	for (;;) {
		i = recv(sock_pd, buf, sizeof(buf), 0);
		if (i < 0) {
			puts("error to receive.");
			exit(-1);
		}
		if (i == 0)
			continue;
		if(myaddr.sa_family == ARPHRD_ETHER){
			print_ethaddr(buf);
			hexdump(buf, i);
		}
	}
}

int main(int argc,char* argv[]){
	//相手が現在生きてるか否かのチェック
	//存在を確認できるまでループ
	
	//送信処理
	prepare_sock();
	while(1){
		send_syn();
	}
	//receive();

	exit_sock();
	return 0;
}
