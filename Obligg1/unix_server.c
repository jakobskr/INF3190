#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#define BUF_SIZE 1500

int main(int argc, char* argv[])
{

  char* sockpath = argv[1];
  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (sock == -1) {
    perror("main: socket()");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strncpy(sockaddr.sun_path, sockpath, sizeof(sockaddr));

  if(bind(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
    perror("bind()");
    exit(EXIT_FAILURE);
  }

  if (listen(sock, 100)) {
    perror("main: listen()");
    exit(EXIT_FAILURE);
  }

  socklen_t addrlen = sizeof(sockaddr);
  int fd = accept(sock, (struct sockaddr *)&sockaddr, &addrlen);

  if (fd == -1) {
    perror("main: accept()");
    exit(EXIT_FAILURE);
  }

  for (;;) {
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

    ssize_t ret = recvmsg(fd, &message, 0);
    fprintf(stdout, "ret: %ld\n", ret);
    if (ret == -1) {
      perror("main: recvmsg()");
      return -1;
    } else if(ret == 0) {
      fprintf(stdout, "connection terminated\n");
      return -1;
    }
    fprintf(stdout, "Motatt: %s\n", buf);
  }
  close(sock);

  return 0;
}
