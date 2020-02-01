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
  unsigned char mip_src;
  unsigned char mip_dst;
  int fd;
  uint8_t src_mac[6];
  uint8_t dst_mac[6];
  struct arp_cache *arp_next;
};

struct epoll_control {
  int epoll_fd;
  int unix_fd;
  int eths_fd[MAX_MIPS];
  int connected_unix;
  struct epoll_event events[MAX_EVENTS];
};

struct fdInfo {
  char *family;
  int listen;
  int fd;
};

struct msg_list {
  unsigned char mip_dst;
  struct msg_list* msg_next;
  char msg[];
};

unsigned char mips[MAX_MIPS] = {0};
char empty_mac[6] = {0};
char brodcast_mac[] = {255,255,255,255,255,255};
int numbMIPS = 0;
int debug = 0;
struct arp_cache *arp_cache_list = NULL;
struct msg_list *msg_backlog = NULL;


/**
 * Adds a message to the message backlog, attaches msg to the end of the list.
 * @param msg [the message to be added]
 * if msg_backlog (the root) is NULL, then msg is now the root.
 *
 */
void add_to_backlog(struct msg_list* msg) {
  if (msg_backlog == NULL) {
    msg_backlog = msg;
    return;
  }
  struct msg_list* msg_current = msg_backlog;
  while (msg_current != NULL) {
    if (msg_current->msg_next == NULL) {
      msg_current->msg_next = msg;
      return;
    }
    msg_current = msg_current->msg_next;
  }
}


/**
 * attempts to find a msg with mip_dst equal of dst (input), and removes it from the list and then returns the message
 * @param  dst [the mip_adress we are looking for]
 * @return     [returns the first message with mip_dst equal of dst]
 * @return [NULL if the list is empty or it didnt find a msg containing the mip_address]
 */
struct msg_list* get_msg_with_dst(unsigned char dst) {
  if (msg_backlog == NULL) {
    return NULL;
  }
  if (msg_backlog->msg_next == NULL) {
    if (msg_backlog->mip_dst == dst) {
      struct msg_list* msg_current = msg_backlog;
      msg_backlog = NULL;
      return msg_current;
    }
    else return NULL;
  }
  struct msg_list* msg_current = msg_backlog;
  while (msg_current->msg_next != NULL) {
    if (msg_current->msg_next->mip_dst == dst) {
      struct msg_list* temp = msg_current->msg_next;
      msg_current->msg_next = msg_current->msg_next->msg_next;
      return temp;
    }
    msg_current = msg_current->msg_next;
  }
  return NULL;
}

/**
 * adds an arp_cache to the arp_cache table (which is actually a list...)
 * @param new_cache [the arp_cache to be added]
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
 * checks if the given mip_dst adress is a local mip_dst adress,
 * and returns the interface if it is
 * @param  mip_dst
 * @return [returns an arp_cache containing ]
 */
struct arp_cache* dst_in_arp_cache(char mip_dst) {
  struct arp_cache* arp_current = arp_cache_list;
  while (arp_current != NULL) {
    if (mip_dst == arp_current->mip_dst) {
      return arp_current;
    }
    arp_current = arp_current->arp_next;
  }
  return NULL;
}

/**
 * checks if the given mip_dst adress is a local mip_dst adress,
 * and returns the interface if it is
 * @param  mip_dst
 * @return [returns an arp_cache containing ]
 */
struct arp_cache* src_in_arp_cache(char mip_src) {
  struct arp_cache* arp_current = arp_cache_list;
  while (arp_current != NULL) {
    if (mip_src == arp_current->mip_src) {
      return arp_current;
    }
    arp_current = arp_current->arp_next;
  }
  return NULL;
}

/**
 * [attempts to send a transport message over ehternet,]
 * @param  arp_current [the arp_cache containing the mip_adresses and mac adresses we need]
 * @param  msg         [the message to be transported]
 * @return             [returns 0 or -1, but i didnt have time to implement error handling for this]
 */
int send_transport_message(struct arp_cache* arp_current, char* msg) {
  struct mip_frame* mip_ramme;
  struct ethernet_frame* eth_ramme;

  size_t mip_size = sizeof(struct mip_frame) + strlen(msg) + 1;
  if (mip_size > 1400) {
    printf("MIP_PACKAGE EXCEEDS 1500 BYTE\nMESSAGE DISCARDED\n");
    return 0;
  }
  mip_ramme = malloc(mip_size);
  mip_ramme->tra = 4;
  mip_ramme->mip_dst = arp_current->mip_dst;
  mip_ramme->mip_src = arp_current->mip_src;
  mip_ramme->pay_length = (strlen(msg) + 1) / 4;
  mip_ramme->ttl = 15;
  strcpy(mip_ramme->content, msg);
  size_t msg_size = sizeof(struct ethernet_frame) + mip_size;
  eth_ramme = malloc (msg_size);
  memcpy(eth_ramme->destination, arp_current->dst_mac, 6);
  memcpy(eth_ramme->source, arp_current->src_mac, 6);
  eth_ramme->protocol=htons(ETH_P_MIP);
  memcpy(eth_ramme->msg, mip_ramme, mip_size);
  int ret = send(arp_current->fd, eth_ramme, msg_size, 0);
  if (ret == -1 ) {
    perror("epoll_event: transport");
    return -1;
  }

  if (debug) {
    printf("TRANSPORT MSG OF %d BYTES SENT VIA ETHERNET\n", ret);
  }

  return 0;
}

int send_message_wo_payload(uint8_t tra, struct arp_cache* arp_current, unsigned char mip_addr) {
  struct mip_frame* mip_ramme;
  struct ethernet_frame* eth_ramme;
  size_t mip_size = sizeof(struct mip_frame);
  mip_ramme = malloc(mip_size);
  mip_ramme->tra = tra;
  mip_ramme->mip_dst = mip_addr;
  mip_ramme->mip_src = arp_current->mip_src;
  mip_ramme->pay_length = 0;
  mip_ramme->ttl = 15;
  size_t msg_size = sizeof(struct ethernet_frame) + mip_size;
  eth_ramme = malloc (msg_size);
  memcpy(eth_ramme->source, arp_current->src_mac, 6);

  if (tra == 0) {
    memcpy(eth_ramme->destination,arp_current->dst_mac,6);
  }
  if (tra == 1) {
    memcpy(eth_ramme->destination, brodcast_mac, 6);
  }

  eth_ramme->protocol = htons(ETH_P_MIP);
  memcpy(eth_ramme->msg, mip_ramme, mip_size);
  int ret = send(arp_current->fd, eth_ramme, msg_size, 0);

  if (ret == -1) {
    perror("epoll_event(): send()");
    exit(EXIT_FAILURE);
  }

  if (tra == 0) {
    if (debug) {
      printf("ARP RESPONSE OF %d BYTES SENT VIA ETHERNET\n", ret);
    }
  }

  if (tra == 1) {
    if (debug) {
      printf("ARP REQUESTOF %d BYTES SENT VIA ETHERNET\n", ret);
    }
  }

  free(eth_ramme);
  free(mip_ramme);
  return 0;
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
      break;
    }

    struct sockaddr *addr = ifaddr->ifa_addr;
    if (addr->sa_family != AF_PACKET) {
      ifaddr = ifaddr->ifa_next;
      continue;
    }

    if (strcmp(ifaddr->ifa_name, "lo") == 0) {
      ifaddr = ifaddr->ifa_next;
      continue;
    }

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
    cache->mip_src = mips[fds_created];
    cache->mip_dst = 0;
    memcpy(cache->src_mac,ifr.ifr_hwaddr.sa_data, 6);
    memcpy(cache->dst_mac,empty_mac, 6);
    cache->fd = sock;
    cache->arp_next = NULL;
    add_to_list(cache);
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
  if (debug) {
    printf("ADDED AN %s SOCKET WITH SD: %d \n",family, fd );
  }
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

/**
 * This functions fires up when the epoll register an EPOLLIN event, it checks if it is from an unix or ehternet sockets, and
 * then handles the message accordingly. If it is an message from unix, it parses the message and attemps to send it to the correct
 * mip daemon. If the message is from ethernet, then it checks the TRA bit and acts accordingly.
 * @param  epctrl [an struct which contains information about the sockets, and the epoll fd)]
 * @param  n      [index of which event we are handling know]
 * @return        [returns nothing of interest, i didnt have time to do error handling]
 */
int epoll_event(struct epoll_control *epctrl, int n)
{
  struct fdInfo *info = epctrl->events[n].data.ptr;
  int connect_sock;

  /**
   * [unix_socket part]
   */
  if (strcmp(info->family, "unix") == 0) {
    if (info->listen == 1 && epctrl->connected_unix == 0) {
      struct sockaddr_un sockaddr = {0};
      sockaddr.sun_family = AF_UNIX;
      socklen_t addrlen = sizeof(sockaddr);

      connect_sock = accept(epctrl->unix_fd, (struct sockaddr *)&sockaddr, &addrlen);
      if (connect_sock == -1) {
        perror("epoll_event: accept()");
        exit(EXIT_FAILURE);
      }

      epctrl->connected_unix = connect_sock;
      epoll_add(epctrl, connect_sock, 0, "unix");
      if (debug) {
        fprintf(stdout, "NEW UNIX CONNECTION ESTABLISHED\n");
      }
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

      ssize_t ret = recvmsg(epctrl->connected_unix, &message, MSG_NOSIGNAL);
      if (ret == 0) {
        epoll_ctl(epctrl->epoll_fd, EPOLL_CTL_DEL, epctrl->connected_unix, 0);
        close(epctrl->connected_unix);
        epctrl->connected_unix = 0;
        if (debug) {
          fprintf(stdout, "UNIX CONNECTION CLOSED\n");
        }
        return 0;
      } else if (ret == -1) {
        perror("epoll_event: recv()");
        exit(EXIT_FAILURE);
      }

      struct arp_cache* arp_dest = dst_in_arp_cache(mip_addr);
      if (arp_dest == NULL) {
        struct arp_cache* arp_current = arp_cache_list;
        if (arp_current == NULL) {
          if (debug) {
            printf("NO VALID INTERFACES\n MESSAGE DISCARDED\n");
          }
          return 0;
        }

        while (arp_current != NULL) {
          if (arp_current->mip_dst == 0) {
            send_message_wo_payload(1,arp_current, mip_addr);
            struct msg_list* msg_temp = malloc(sizeof(struct msg_list) + strlen(buf) + 1);
            msg_temp->mip_dst = mip_addr;
            msg_temp->msg_next = NULL;
            strcpy(msg_temp->msg, buf);
            add_to_backlog(msg_temp);
          }
          arp_current = arp_current->arp_next;
        }
        return 0;
        //mip
      }

      else {
        send_transport_message(arp_dest, buf);
      }
    }
  }

  /**
   * [ethernet_socket part!]
   */
  else {
    char buf[BUF_SIZE];
    recv(info->fd, buf, sizeof(buf),0);
    struct ethernet_frame* eth_ramme = (struct ethernet_frame*) buf;
    struct mip_frame* mip_ramme = (struct mip_frame*) eth_ramme->msg;

    if (debug) {
      printf("TRA: %d \n", mip_ramme->tra);
      printf("SOURCE MIP: %d\n",mip_ramme->mip_src);
      printf("PAYLOAD LENGTH: %d\n", (mip_ramme->pay_length * 4));
      printf("SOURCE MAC_ADDR: ");
      for (int i = 0; i < 6; i++) {
        printf("%d ",eth_ramme->source[i]);
      }
      printf("\n");
      printf("DESTINATION MIP: %d\n", mip_ramme->mip_dst);
      printf("DESTINATION MAC_ADDR: ");
      for (int i = 0; i < 6; i++) {
        printf("%d ",eth_ramme->destination[i]);
      }
      printf("\n");
    }

    struct arp_cache* arp_current;

    //handling the message
    if (mip_ramme->tra == 1) {
      arp_current = src_in_arp_cache(mip_ramme->mip_dst);
      if (arp_current == NULL) {
        return 0;
      }

      if (arp_current->fd != info->fd) {
        return 0;
      }

      if (arp_current->mip_dst == 0) {
        arp_current->mip_dst = mip_ramme->mip_src;
        memcpy(arp_current->dst_mac, eth_ramme->source,6);
      }

      send_message_wo_payload(0, arp_current, arp_current->mip_dst);
      return 0;
    }

    else if (mip_ramme->tra == 2) {
      /****
       * In preperation of home exam :))))
       */
    }

    else if (mip_ramme->tra == 4) {
      if (epctrl->connected_unix == 0) {
        if (debug) {
          printf("NO LOCAL APPLICATIONS CONNECTED\nMESSAGE DISCARDED\n");
        }
        return 0;
      }
      char buf[BUF_SIZE] = {0};

      //printf("mip_ramme-> content %s\n",mip_ramme->content );
      strcpy(buf, mip_ramme->content);
      int mip_addr =  mip_ramme->mip_src;
      struct iovec iov2[2];
      iov2[0].iov_base = (buf);
      iov2[0].iov_len = sizeof(buf);

      iov2[1].iov_base = &mip_addr;
      iov2[1].iov_len = sizeof(unsigned char);

      struct msghdr message = {0};
      message.msg_iov = iov2;
      message.msg_iovlen = 2;
      ssize_t ret = sendmsg(epctrl->connected_unix, &message, MSG_NOSIGNAL);
      if(ret == -1) {
        close(epctrl->connected_unix);
        epctrl->connected_unix = 0;
        return 0;
      }
      if (debug) {
        fprintf(stdout, "SENT %ld BYTES TO CLIENT VIA UNIX \n", ret);
      }
    }

    else if (mip_ramme->tra == 0) {

      if (debug) {
        printf("RECIEVED ARP RESPONE, ARP_CACHE TABLE UPDATED\n");
      }

      arp_current = src_in_arp_cache(mip_ramme->mip_dst);
      if (arp_current == NULL) {
        return 0;
      }

      if (arp_current->mip_dst == 0) {
        arp_current->mip_dst = mip_ramme->mip_src;
        memcpy(arp_current->dst_mac, eth_ramme->source,6);
      }
      struct msg_list* msg_current = get_msg_with_dst(arp_current->mip_dst);
      while (msg_current != NULL) {
        send_transport_message(arp_current, msg_current->msg);
        msg_current = get_msg_with_dst(arp_current->mip_dst);
      }
      return 0;
    }
  }
  return 0;
}

/**
 * [sets up the unix socket and ethernets sockets, creates and start a epoll with. And then calls epoll_wait in neverending loop]
 * @param  argc [number of arguments from user]
 * @param  argv [the arguments]
 *
 */
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
  printf(CYN"MIP DAEMON STARTED\n" RESET );
  struct epoll_control epctrl;
  epctrl.epoll_fd = epoll_create(99);
  epctrl.connected_unix = 0;
  if (epctrl.epoll_fd == -1) {
    perror("main: epoll_create()");
    exit(EXIT_FAILURE);
  }

  epctrl.unix_fd = setup_unix_socket(sockpath);
  epoll_add(&epctrl, epctrl.unix_fd, 1 , "unix");
  memset(epctrl.eths_fd,0,sizeof(epctrl.eths_fd));
  int ethsocks_created = setup_ethernet_socks(epctrl.eths_fd);

  if (debug) {
    printf("CREATED %d EHTERNET SOCKETS\n",ethsocks_created);
  }

  for (int i = 0; i < ethsocks_created; i++) {
    epoll_add(&epctrl, epctrl.eths_fd[i], 1 , "ethernet");
  }

  printf(CYN "SET-UP FINISHED\nENTERING epoll_wait LOOP\n" RESET );
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
