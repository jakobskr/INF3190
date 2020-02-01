#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <poll.h>

#include "colours.h"

#define BUF_SIZE 1500
/**
 * A simple client program which attemst to ping a sever at a given mip Adress.
 * It times out after waiting 1 second for answer.
 * it prints out the pong signal and timed elapsed between sending and recieving a response, and then exits.
 *
 */
int main (int argc, char* argv[]) {
  if (strcmp(argv[1],"-h") == 0) {
    printf("this program attempts to ping a ping_server at the given mip adress\n");
    printf("COMMANDS: \n");
    printf("-h: prints help without executing the program!\n");
    printf("Usage: %s <destination_host> <Message> <Socket Application>\n", argv[0]);
    exit(0);
  }

  if (argc < 4) {
    printf(RED "Usage: %s [-h] <destination_host> <Message> <Socket Application>\n" RESET , argv[0]);
    exit(EXIT_FAILURE);
  }

  printf("%s %zd \n",argv[2], strlen(argv[2]));

  char* sockpath = argv[3];
  char* msg = argv[2];
  if ((strlen(msg) + 1)  % 4 != 0) {
    printf("Message length has to be a multiple of 4!\n");
    exit(EXIT_FAILURE);
  }
  char buf[BUF_SIZE] = {0};
  strncpy(buf, msg, strlen(msg));
  printf("%s %zd\n",buf, strlen(buf));
  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

  if (sock == -1) {
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path, sockpath);

  if (connect(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1) {
    perror("main: connect()");
    exit(EXIT_FAILURE);
  }

  int mip_addr = atoi(argv[1]);
  struct iovec iov[2];
  iov[0].iov_base = buf;
  iov[0].iov_len = sizeof(buf);

  iov[1].iov_base = &mip_addr;
  iov[1].iov_len = sizeof(mip_addr);

  struct msghdr message = {0};
  message.msg_iov = iov;
  message.msg_iovlen = 2;
  ssize_t ret = sendmsg(sock, &message, 0);

  if (ret == -1) {
    perror("main: sendmsg()");
    exit(EXIT_FAILURE);
  }

  struct timeval *sendtime = malloc(sizeof(struct timeval));
  gettimeofday(sendtime,NULL);

  printf("%d\n",mip_addr);
  memset(buf, 0, BUF_SIZE);
  mip_addr = 0;

  iov[0].iov_base = buf;
  iov[0].iov_len = sizeof(buf);

  iov[1].iov_base = &mip_addr;
  iov[1].iov_len = sizeof(mip_addr);

  struct msghdr message2 = {0};
  message2.msg_iov = iov;
  message2.msg_iovlen = 2;
  struct pollfd fd;
  int ret2;
  fd.fd = sock;
  fd.events = POLLIN;
  ret2 = poll(&fd, 1, 1000);

  if (ret2 == -1) {
    printf("polling error :()\n");
    exit(EXIT_FAILURE);
  }

  else if (ret2 == 0) {
    printf("Pingc: TIMEOUT\n");
    exit(0);
  }

  ret = recvmsg(sock, &message2, 0);

  struct timeval* recievetime = malloc(sizeof(struct timeval));
  gettimeofday(recievetime, NULL);
  int sec = (int)(recievetime->tv_sec-sendtime->tv_sec);
	int usec = (int)(recievetime->tv_usec-sendtime->tv_usec)/1000;
  if (ret == -1) {
    perror("main: recvmsg()");
    return -1;
  } else if(ret == 0) {
    fprintf(stdout, "connection terminated\n");
    return -1;
  }
  close(sock);
  fprintf(stdout, "msg: %s from: %d in %ds: %dms\n",buf, mip_addr, sec, usec);
  return 0;
}
