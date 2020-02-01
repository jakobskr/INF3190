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

#include "get_interface_names.c"
//#include "get_mac.c"
#include "colours.h"

#define BUF_SIZE 1500
#define MAX_EVENTS 10
#define ETH_P_MIP 0x88B5
#define MAX_MIPS 10

struct ethernet_frame {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t protocol;
  char msg[];
} __attribute__((packed));

struct mip_frame {
  uint8_t tra:3;
  unsigned char mip_dst:8;
  unsigned char mip_src:8;
  uint16_t pay_length:9;
  uint8_t ttl:4;
  char content[];
}__attribute__((packed));

struct arp_cache {
  unsigned char src_mip;
  unsigned char dst_mip;
  int fd;
  uint8_t src_mac[6];
  uint8_t dst_mac[6];
  struct arp_cache *arp_next;
};

struct epoll_control {
  int epoll_fd;
  int unix_fd;
  int eths_fd[MAX_MIPS];
  struct epoll_event events[MAX_EVENTS];
};

struct fdInfo {
  char *family;
  int listen;
  int fd;
};

unsigned char mips[MAX_MIPS] = {0};
char empty_mac[6] = {0};
char brodcast_mac[] = {255,255,255,255,255,255};
int numbMIPS = 0;
int debug = 0;
struct arp_cache *arp_cache_list = NULL;

/**
 * [add_to_list description]
 * @param new_cache [description]
 */
void add_to_list(struct arp_cache* new_cache) {
  struct arp_cache* arp_current = arp_cache_list;
  if (arp_current == NULL) {
    arp_cache_list = new_cache;
    return;
  }
  while (arp_current != NULL) {
    if (arp_current->arp_next == NULL ) {
      arp_current->arp_next = new_cache;
      return;
    }
    arp_current = arp_current->arp_next;
  }
}
/**
 * checks if the given dst_mip adress is a local dst_mip adress,
 * and returns the interface if it is
 * @param  dst_mip
 * @return [returns an arp_cache containing ]
 */
struct arp_cache* check_arp_cache(char dst_mip) {
  struct arp_cache* arp_current = arp_cache_list;
  while (arp_current != NULL) {
    printf("infinite loop her ?\n");
    if (dst_mip == arp_current->dst_mip) {
      return arp_current;
    }
    arp_current = arp_current->arp_next;
  }
  return NULL;
}

int setup_unix_socket(char* sockpath) {
  int sock_un = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path, sockpath);

  unlink(sockpath);
  if(bind(sock_un, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
    perror("setup_unix_socket: bind()");
    exit(EXIT_FAILURE);
  }

  if (listen(sock_un, 100)) {
    perror("setup_unix_socket: listen()");
    exit(EXIT_FAILURE);
  }

  return sock_un;
}

int setup_ethernet_socks(int *fds) {
  struct ifaddrs *ifstart, *ifaddr;
  int fds_created = 0;
  if (getifaddrs(&ifaddr) == -1) {
    perror("setup_ethernet_socks(): getifaddrs(): ");
    exit(EXIT_FAILURE);
  }

  ifstart = ifaddr;
  while (ifaddr != NULL) {

    if (fds_created == numbMIPS) {
      printf("No more mips adresses!\n");
      break;
    }

    struct sockaddr *addr = ifaddr->ifa_addr;
    if (addr->sa_family != AF_PACKET) {
      ifaddr = ifaddr->ifa_next;
      continue;
    }

    if (strcmp(ifaddr->ifa_name, "lo") == 0) {
      printf("Into the trash it goes :)))))))\n");
      ifaddr = ifaddr->ifa_next;
      continue;
    }

    fprintf(stderr, "Interface: %s\n", ifaddr->ifa_name);

    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    strcpy(ifr.ifr_name, ifaddr->ifa_name);
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
    if (sock == -1) {
      perror("setup_ethernet_socks(): socket():");
      exit(EXIT_FAILURE);
    }

    struct sockaddr_ll sockaddr;
    memset(&sockaddr, 0, sizeof(struct sockaddr_ll));

    if (ioctl(sock,SIOCGIFINDEX, &ifr) == -1) {
      perror("setup_ethernet_socks(): ioctl():");
      exit(EXIT_FAILURE);
    }

    sockaddr.sll_ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
      perror("setup_ethernet_socks(): ioctl:");
      exit(EXIT_FAILURE);
    }

    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_MIP);

    if (bind(sock, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_ll)) == -1) {
      perror("setup_ethernet_socks(): bind():");
      exit(EXIT_FAILURE);
    }

    struct arp_cache* cache = malloc(sizeof(struct arp_cache));
    memset(cache, 0, sizeof(struct arp_cache));
    printf("%d dette er mip\n",mips[fds_created]);
    cache->src_mip = mips[fds_created];
    cache->dst_mip = 0;
    //memcpy(cache->src_mac,ifr.ifr_hwaddr.sa_data, 6);
    //memcpy(cache->dst_mac,empty_mac, 6);
    cache->fd = sock;
    cache->arp_next = NULL;
    printf("%d %d\n",cache->dst_mip,cache->src_mip);
    add_to_list(cache);
    free(cache);
    fds[fds_created] = sock;
    fds_created++;
    ifaddr = ifaddr->ifa_next;
  }
  freeifaddrs(ifstart);
  return fds_created;
}

int epoll_add(struct epoll_control *epctrl, int fd, int listening, char *family)
{
  //NB: HVis du bruker EPOLLET -> så må socket være NONBLOCKING
  printf("%d %d %s\n",fd, listening,family );
  struct fdInfo *info = malloc(sizeof(struct fdInfo) + strlen(family) + 1);
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  info->listen = listening;
  info->family = family;
  info->fd = fd;
  ev.data.ptr = info;
  if (epoll_ctl(epctrl->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    perror("epoll_add: epoll_ctl()");
    exit(EXIT_FAILURE);
  }
  return 0;
}

int epoll_event(struct epoll_control *epctrl, int n)
{
  struct fdInfo *info = epctrl->events[n].data.ptr;
  int connect_sock;
  printf("%s  %d  %d\n",info->family, info->listen,info->fd);
  //cheks if it is unix soccet.
  if (strcmp(info->family, "unix") == 0) {
    if (info->listen == 1) {
      struct sockaddr_un sockaddr = {0};
      sockaddr.sun_family = AF_UNIX;
      socklen_t addrlen = sizeof(sockaddr);

      connect_sock = accept(epctrl->unix_fd, (struct sockaddr *)&sockaddr, &addrlen);
      if (connect_sock == -1) {
        perror("epoll_event: accept()");
        exit(EXIT_FAILURE);
      }

      epoll_add(epctrl, connect_sock, 0, "unix");
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

      ssize_t ret = recvmsg(info->fd, &message, 0);
      if (ret == 0) {
        //connection closed
        //TODO: remove fd/socket from EPOLL: EPOLL_CTL_DEL
        //epoll_ctl(epctrl)
        fprintf(stdout, "Connection closed\n");
        return 0;
      } else if (ret == -1) {
        perror("epoll_event: recv()");
        exit(EXIT_FAILURE);
      }

      struct arp_cache* arp_dest = check_arp_cache(mip_addr);
      struct ethernet_frame* eth_ramme = NULL;
      struct mip_frame* mip_ramme = NULL;
      if (arp_dest == NULL) {
        //fant ikke dst_mip i cachen, må sende ut en arp request!
        struct arp_cache* arp_current = arp_cache_list;
        if (arp_current == NULL) {
          printf("No valid interfaces, printing message locally instead :(\n");
          fprintf(stdout, "Mip_addr: %d\nMsg: %s ret: %zd\n", mip_addr, buf, ret);
          return 0;
        }

        while (arp_current != NULL) {
          printf("AWOOOOOOO\n");
          printf("fakk a u american bitch %d\n",arp_current->dst_mip);
          if (arp_current->dst_mip == 0) {
            printf("%d reeee\n",arp_current->src_mip);
            size_t mip_size = sizeof(struct mip_frame);
            mip_ramme = malloc(mip_size);
            mip_ramme->tra = 1;
            mip_ramme->mip_dst = mip_addr;
            mip_ramme->mip_src = arp_current->src_mip;
            mip_ramme->pay_length = 0;
            mip_ramme->ttl = 15;
            size_t msg_size = sizeof(struct ethernet_frame) + mip_size;
            eth_ramme = malloc (msg_size);
            memcpy(eth_ramme->destination, brodcast_mac, 6);
            memcpy(eth_ramme->source, arp_current->dst_mac, 6);
            eth_ramme->protocol = htons(ETH_P_MIP);
            memcpy(eth_ramme->msg, mip_ramme, mip_size);

            printf("%d\n",arp_current->src_mip);
            for(int i = 0; i < 6; i++) {
              printf("%d.",eth_ramme->source[i] );
            }
            printf("\n");
            int ret = send(arp_current->fd, eth_ramme, msg_size, 0);
            free(eth_ramme);
            free(mip_ramme);
            if (ret == -1) {
              perror("epoll_event(): send()");
              exit(EXIT_FAILURE);
            }
            printf( "sent %d bytes\n", ret);
          }
          arp_current = arp_current->arp_next;
        }
        return 0;
        //mip
      }
      else
      //struct ethernet_frame *

      fprintf(stdout, "Mip_addr: %d\nMsg: %s ret: %zd\n", mip_addr, buf, ret);
    }
  }

  //ethernet recv
  else {
    printf("HOLY FUCK I RECIEVED AN EHTERNET MSG !!!!!!\n");
    char buf[BUF_SIZE];
    recv(info->fd, buf, sizeof(buf),0);
    struct ethernet_frame* eth_ramme = (struct ethernet_frame*) buf;
    for(int i = 0; i < 6; i++) {
      printf("%d.",eth_ramme->source[i] );
    }
    printf("\n");
    for(int i = 0; i < 6; i++) {
      printf("%d.",eth_ramme->destination[i] );
    }
    printf("\n");

    struct mip_frame* mip_ramme = (struct mip_frame*) eth_ramme->msg;

    printf("%d %d \n", mip_ramme->mip_src, mip_ramme->mip_dst);
    //dump_frame(ramme);

    // if (info->listen == 1) {
    //
    //
    // }
    //
    // else {
    //   //TODO: add message recv
    // }
  }

  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf(RED "usage: [-h] <socket_applictaion> [mip_addresses]\n" RESET );
    exit(0);
  }
  char* sockpath;
  if (strcmp (argv[1],  "-h") == 0) {
    printf("commands:\n");
    exit(0);
  }
  else if (strcmp(argv[1], "-d") == 0) {
    debug = 1;
    sockpath = argv[2];
    numbMIPS = argc - 3;
    printf("%d\n",numbMIPS);
    for(int i = 0; i < argc - 3; i++) {
      mips[i] = atoi(argv[i + 3]);
    }
  }
  else {
    sockpath = argv[1];
    numbMIPS = argc - 2;
    printf("%d\n",numbMIPS);
    for(int i = 0; i < argc - 2; i++) {
      mips[i] = atoi(argv[i + 2]);
    }
  }
  struct epoll_control epctrl;
  epctrl.epoll_fd = epoll_create(99);
  if (epctrl.epoll_fd == -1) {
    perror("main: epoll_create()");
    exit(EXIT_FAILURE);
  }

  epctrl.unix_fd = setup_unix_socket(sockpath);
  printf("unix_fd: %d\n",epctrl.unix_fd);
  epoll_add(&epctrl, epctrl.unix_fd, 1 , "unix");
  //this works on ubuntu!
  memset(epctrl.eths_fd,0,sizeof(epctrl.eths_fd));

  //int ethsocks_created = 0;
  int ethsocks_created = setup_ethernet_socks(epctrl.eths_fd);

  printf("created this many socks :) %d\n",ethsocks_created);

  for (int i = 0; i < ethsocks_created; i++) {
    epoll_add(&epctrl, epctrl.eths_fd[i], 1 , "ethernet");
  }

  printf("kommer vi hit ?\n");
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
  close(epctrl.unix_fd);

}
