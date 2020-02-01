#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "colours.h"
#define BUF_SIZE 1500
#define PONG "PONG"

/**
 * A simple server program which reads data from an socket. prints it out then sends out a pong reply signal
   the program runs until forcibly exited, becuase thats how i interpreted  the ping_server.
 */
int main(int argc, char* argv[])
{

  if (strcmp(argv[1],"-h") == 0) {
    printf("this program attempts to recieve pings from a client via a mip daemon, and returns a PONG\n");
    printf("COMMANDS: \n");
    printf("-h: prints help without executing the program!\n");
    printf("Usage: %s <Socket Application>\n", argv[0]);
    exit(0);
  }

  if (argc < 2) {
    printf(RED "Wrong Usage of program\n" RESET);
    printf(RED "Usage: %s ping_server [-h] <Socket_application\n" RESET, argv[0]);
    exit(EXIT_FAILURE);
  }

  char* sockpath = argv[1];
  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (sock == -1) {
    perror("main: socket()");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strncpy(sockaddr.sun_path, sockpath, sizeof(sockaddr));

  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
    perror("main: connect()");
    exit(EXIT_FAILURE);
  }

    while (1) {
      char buf[BUF_SIZE] = {0};
      int mip_addr;

      struct iovec iov[2];
      iov[0].iov_base = buf;
      iov[0].iov_len = sizeof(buf);

      iov[1].iov_base = &mip_addr;
      iov[1].iov_len = sizeof(mip_addr);

      struct msghdr message = {0};
      message.msg_iov = iov;
      message.msg_iovlen = 2;

      ssize_t ret = recvmsg(sock, &message, 0);
      fprintf(stdout, "ret: %ld\n", ret);
      if (ret == -1) {
        perror("main: recvmsg()");
        return -1;
      } else if(ret == 0) {
        fprintf(stdout, "connection terminated\n");
        return -1;
      }
      fprintf(stdout, "Motatt: %s\n mip_addr: %d", buf, mip_addr);
      strncpy(buf,"PONG", sizeof("PONG"));
      iov[0].iov_base = buf;
      iov[0].iov_len = sizeof(buf);

      ret = sendmsg(sock, &message, 0);
      if(ret == -1) {
        perror("main: sendmsg()");
        exit(EXIT_FAILURE);
      }
      fprintf(stdout, "ret: %ld\n", ret);
    }

  close(sock);

  return 0;
}
