#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#define BUF_SIZE 1500

/**
 * [main description]
 * @param  argc [description]
 * @param  argv [description]
 * @return      [description]
 */
int main(int argc, char* argv[])
{
  // argv[1] == socketname
  // argv[2] == message

  char* sockpath = argv[1];
  char* msg = argv[2];
  char buf[BUF_SIZE] = {0};
  strncpy(buf, msg, strlen(msg));

  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

  if (sock == -1) {
    perror("socket()");
    return -1;
  }

  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path, sockpath);

  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
    perror("main: connect()");
    exit(EXIT_FAILURE);
  }

  int mip_addr = atoi(argv[3]);
  struct iovec iov[2];
  iov[0].iov_base = buf;
  iov[0].iov_len = sizeof(buf);

  iov[1].iov_base = &mip_addr;
  iov[1].iov_len = sizeof(mip_addr);

  struct msghdr message = {0};
  message.msg_iov = iov;
  message.msg_iovlen = 2;

  ssize_t ret = sendmsg(sock, &message, 0);
  if(ret == -1) {
    perror("main: sendmsg()");
    exit(EXIT_FAILURE);
  }
  fprintf(stdout, "ret: %ld\n", ret);

  return 0;
}
