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



int main(int argc, char* args[]) {
	if (argc < 3) {
		printf("Expected  3 arguments\n");
		printf("Given %d arguments\n", argc);
		printf("Usage: %s <MIPTP_PATH> <PORT>\n" , args[0]);
		exit(EXIT_FAILURE);
	}

	int files_written = 0;
	char *sockpath = args[1];

	int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

	if (sock == -1) {
		perror("main: socket(): ");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_un sockaddr;
	sockaddr.sun_family = AF_UNIX;
	strncpy(sockaddr.sun_path, sockpath, sizeof(sockaddr));
	
	if (connect (sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == - 1) {
		perror("main: connect(): ");
		exit(EXIT_FAILURE);
	}
	
	uint16_t port = strtol(args[2], 0, 10); 
	unsigned char hello[3];
	hello[0] = 255;
	memcpy(hello + 1, &port, sizeof(port));

	ssize_t sb = send(sock, hello, sizeof(hello), 0);

	if (sb == - 1)	{
		printf("failed to say hello to miptp\n");
		exit(EXIT_FAILURE);
	}

	/*
	send number to miptp using 255 as a signal for ports
	*/
	while(1) {
		char buf[66000] = {0};
		char filepath[20];
		snprintf(filepath, 20, "%i_recieved_file%i", port,files_written);
		ssize_t ret = recv(sock, buf, sizeof(buf), 0);

		if (ret == -1) {
			perror("main: recv()");
			EXIT_FAILURE;
		}

		if (ret == 0) {
			printf("main: recv: connection closed\n");
			exit(0);
		}
		
		printf("filepath %s \n",filepath );

		uint16_t file_size = 0;
		memcpy(&file_size, buf, 2);

		FILE *file = NULL;
		file = fopen(filepath, "w");

		if (file == NULL) {
			printf("Could not open %s", filepath);
		}

		for(int ch = 2; ch < file_size; ch++){
			fputc(buf[ch], file);
		}

		

		//printf("%s\n", buf + 2);

		printf(" vs length %d vs ret %zd \n", file_size, ret);


		printf("%d\n",file_size );
		fclose(file);
		files_written++;
	}
}