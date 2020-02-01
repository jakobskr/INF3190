#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/epoll.h>

#define BUF_SIZE 1500
#define MAX_EVENTS 10

struct epoll_control {
  int epoll_fd;
  int accept_fd;
  struct epoll_event events[MAX_EVENTS];
};

int epoll_add(struct epoll_control *epctrl, int fd)
{
  //NB: HVis du bruker EPOLLET -> så må socket være NONBLOCKING
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = fd;
  if (epoll_ctl(epctrl->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    perror("epoll_add: epoll_ctl()");
    exit(EXIT_FAILURE);
  }
  return 0;
}

int epoll_event(struct epoll_control *epctrl, int n)
{
  int connect_sock;
  struct sockaddr_un sockaddr = {0};
  sockaddr.sun_family = AF_UNIX;
  socklen_t addrlen = sizeof(sockaddr);

  if (epctrl->events[n].data.fd == epctrl->accept_fd) {
    connect_sock = accept(epctrl->accept_fd, (struct sockaddr *)&sockaddr, &addrlen);
    if (connect_sock == -1) {
      perror("epoll_event: accept()");
      exit(EXIT_FAILURE);
    }

    epoll_add(epctrl, connect_sock);
    fprintf(stdout, "New connection established\n");
  } else {
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

    ssize_t ret = recvmsg(epctrl->events[n].data.fd, &message, 0);
    if (ret == 0) {
      //connection closed
      //TODO: remove fd/socket from EPOLL: EPOLL_CTL_DEL
      fprintf(stdout, "Connection closed\n");
      return 0;
    } else if (ret == -1) {
      perror("epoll_event: recv()");
      exit(EXIT_FAILURE);
    }
    fprintf(stdout, "Mip_addr: %d\nMsg: %s\n", mip_addr, buf);
  }

  return 0;
}


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
  strcpy(sockaddr.sun_path, sockpath);

  if(bind(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
    perror("bind()");
    exit(EXIT_FAILURE);
  }

  if (listen(sock, 100)) {
    perror("main: listen()");
    exit(EXIT_FAILURE);
  }

  struct epoll_control epctrl;
  epctrl.accept_fd = sock;
  epctrl.epoll_fd = epoll_create(99);

  if(epctrl.epoll_fd == -1) {
    perror("main: epoll_create()");
    exit(EXIT_FAILURE);
  }

  //epoll_add(&epctrl, epctrl.accept_fd);
  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.fd = sock; //listen/accept socket, den vi bruker til accept() funksjonen
  if (epoll_ctl(epctrl.epoll_fd, EPOLL_CTL_ADD, epctrl.accept_fd, &ev) == -1) {
     perror("epoll_ctl: listen_sock");
     exit(EXIT_FAILURE);
  }


  for(;;) {
    int nfds, n;
    nfds = epoll_wait(epctrl.epoll_fd, epctrl.events, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("main: epoll_wait");
      exit(EXIT_FAILURE);
    }
    for (n = 0; n < nfds; n++) {
      epoll_event(&epctrl, n);
    }
  }
  close(sock);

  return 0;
}
