#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define	MAX_LENGTH 65535
#define MAX_PAYLOAD 1492



int main(int argc, char* args[]) {
	
	if (argc != 5) {
		printf("Expected 5 arguments\nGiven %d arguments\n", argc);
		printf("Usage: %s <FILE NAME> <MIPTP_PATH> <MIP ADDR> <PORT>\n", args[0] );
		exit(-1);
	}

	FILE *file_path = NULL;
	uint16_t file_length;
	uint16_t port = 0;

	unsigned char mip_addr = atoi(args[3]);
	char *sockpath = args[2];
	port = strtol(args[4], 0, 10); 
	printf("%d\n", port);

	file_path = fopen(args[1], "r");
	if (file_path == NULL) {
		printf("ERROR: FILE %s could not be opened\n", args[1]);
		exit(-1);
	}

	fseek(file_path, 0, SEEK_END);
	file_length = ftell(file_path);
	rewind(file_path);

	if (file_length > 65535) {
		printf("file_length > 65535\n");
		exit(0);
	}
	
	char file_text[65535] = {0};
	fread(file_text, 1, file_length, file_path);

	printf("%d %s\n",mip_addr, sockpath );

	int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

	if (sock == -1) {
		perror("main(): socket(): ");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_un sockaddr;
	sockaddr.sun_family = AF_UNIX;
	strcpy(sockaddr.sun_path, sockpath);
	
	if (connect(sock, (struct sockaddr*) &sockaddr, sizeof(sockaddr)) == -1) {
		perror("main: Connect");
		exit(EXIT_FAILURE);
	}

	unsigned char buf[66000] = {0};
	memset(buf, 0, sizeof(buf));
	buf[0] = mip_addr;
	memcpy(buf + 1, &port, sizeof(port));
	memcpy(buf + 3, &file_length, sizeof(file_length));
	memcpy(buf + 5, file_text, file_length);

	ssize_t ret = send(sock, buf, file_length + 1 + 4, 0);

	if (ret == - 1) {
		perror("main: send(): ");
		exit(EXIT_FAILURE);
	}

	printf("File_length: %d \nSent %zd bytes to %d %d\n",file_length,ret, mip_addr, port);

	close(sock);
	free(file_path);
}//sad