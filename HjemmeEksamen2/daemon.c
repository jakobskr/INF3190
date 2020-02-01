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

#define BUF_SIZE 1514
#define MAX_EVENTS 10
#define ETH_P_MIP 0x88B5
#define MAX_MIPS 10
#define BROADCAST 255
#define TRA 32 - 3
#define DST TRA - 8
#define SRC DST - 8
#define LENGTH SRC - 9
#define TTLS LENGTH - 4

struct ethernet_frame {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t protocol;
  char msg[];
} __attribute__((packed));

struct mip_frame2 {
  uint32_t header;
  unsigned char content[];
};

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
  int client_fd;
  int rout_fd;
  int forw_fd;
  int eths_fd[MAX_MIPS];
  int connected_unix;
  int connected_forward;
  int connected_router;
  struct epoll_event events[MAX_EVENTS];
};

struct fdInfo {
  char *family;
  int listen;
  int fd;
};

struct arp_backlog {
  unsigned char mip_dst;
  unsigned char tra;
  unsigned int length;
  struct arp_backlog* msg_next;
  unsigned char msg[];
};

struct route_backlog {
  unsigned char mip;
  unsigned char from;
  unsigned int length;
  int ttl;
  struct route_backlog* msg_next;
  unsigned char msg[];
};

//GLOBAL VARIABLES;
unsigned char mips[MAX_MIPS] = {0};
unsigned char empty_mac[6] = {0};
unsigned char broadcast_mac[] = {255,255,255,255,255,255};
int numbMIPS = 0; //number of valid mips read from user at start up
int debug = 0;
struct arp_cache *arp_cache_list = NULL; //arp_cache tabel
struct arp_backlog *msg_backlog = NULL;  //messages waiting for arp response
struct route_backlog *route_log = NULL;  //messages waiting for route look up


/**
 * [create_mip_header description]
 * @param  tra     [description]
 * @param  mip_dst [description]
 * @param  mip_src [description]
 * @param  length  [description]
 * @param  ttl     [description]
 * @return         [description]
 */
uint32_t create_mip_header(int tra, unsigned char mip_dst, unsigned char mip_src, uint length, unsigned char ttl ) {
  uint32_t header = 0;
  printf("%u this i lenght inside cmh\n", length);
  header ^= (-tra ^ header) & (tra << (TRA));
  header ^= (-mip_dst ^ header) & (mip_dst << (DST));
  header ^= (-mip_src ^ header) & (mip_src << (SRC));
  //header ^= ((-length) ^ header) & ((length & 511) << (LENGTH));
  header |= (length & 511) << 4;
  header |= ttl;
  return header;
}

/**
 * Adds a message to the route_backlog, attaches new msg to the end of the list.
 * @param msg [the message to be added]
 * if msg_backlog (the root) is NULL, then msg is now the root.
 */
void add_to_route_backlog(struct route_backlog* msg) {
  if (route_log == NULL) {
    route_log = msg;
    return;
  }
  struct route_backlog* msg_current = route_log;
  while (msg_current != NULL) {
    if (msg_current->msg_next == NULL) {
      msg_current->msg_next = msg;
      return;
    }
    msg_current = msg_current->msg_next;
  }
}


/**
 * returns the oldest message from routing lookup backlog
 */
struct route_backlog* get_msg_from_route_log() {
  if (route_log == NULL) {
    return NULL;

  }
  struct route_backlog *temp = route_log;
  route_log = route_log->msg_next;
  return temp;
}

/**
 * Adds a message to the message backlog, attaches msg to the end of the list.
 * @param msg [the message to be added]
 * if msg_backlog (the root) is NULL, then msg is now the root.
 */
void add_to_arp_backlog(struct arp_backlog* msg) {
  if (msg_backlog == NULL) {
    msg_backlog = msg;
    return;
  }
  struct arp_backlog* msg_current = msg_backlog;

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
struct arp_backlog* get_msg_with_dst(unsigned char dst) {
  if (msg_backlog == NULL) {
    return NULL;
  }

  if (msg_backlog->msg_next == NULL) {
    if (msg_backlog->mip_dst == dst) {
      struct arp_backlog* msg_current = msg_backlog;
      msg_backlog = NULL;
      return msg_current;
    }
    else return NULL;
  }
  struct arp_backlog* msg_current = msg_backlog;

  while (msg_current->msg_next != NULL) {
    if (msg_current->msg_next->mip_dst == dst) {
      struct arp_backlog* temp = msg_current->msg_next;
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
struct arp_cache* dst_in_arp_cache(unsigned char mip_dst) {
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
 * checks if the given mip_src adress is assigned to our mip_daemon,
 * and returns the interface if it is
 * @param  mip_dst
 * @return [returns an arp_cache containing ]
 */
struct arp_cache* src_in_arp_cache(unsigned char mip_src) {
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
 * attempts to forward a message over ethernet to the next jump in the route.
 * @param arp_current   arp_cache of the next jump
 * @param route_current information from the original sender of the message.
 */
void forward_message(struct arp_cache* arp_current, struct route_backlog *route_current) {
  struct mip_frame2* mip_ramme2;
  struct ethernet_frame* eth_ramme;
  size_t mip_size2 = sizeof(struct mip_frame2) + route_current->length;

  if (mip_size2 > 1500) {
    printf("MIP_PACKAGE EXCEEDS 1500 BYTE\nMESSAGE DISCARDED\n");
    return;
  }

  mip_ramme2 = malloc(mip_size2);

  if (route_current->from == 0) {
    mip_ramme2->header = create_mip_header(4, route_current->mip,arp_current->mip_src, route_current->length / 4, route_current->ttl);
  }

  else {
    mip_ramme2->header = create_mip_header(4, route_current->mip,route_current->from, route_current->length / 4, route_current->ttl);
  }

  memcpy(mip_ramme2->content, route_current->msg, route_current->length);

  size_t msg_size = sizeof(struct ethernet_frame) + mip_size2;
  eth_ramme = malloc (msg_size);
  memcpy(eth_ramme->destination, arp_current->dst_mac, 6);
  memcpy(eth_ramme->source, arp_current->src_mac, 6);
  eth_ramme->protocol=htons(ETH_P_MIP);
  memcpy(eth_ramme->msg, mip_ramme2, mip_size2);
  ssize_t ret = send(arp_current->fd, eth_ramme, msg_size, 0);

  if (ret == -1 ) {
    perror("epoll_event: transport");
    return;
  }


  free(eth_ramme);
  free(mip_ramme2);
  return;
}


/**
 * Send a message with payload over ethernet to another daemon. TRA is set to 4;
 * @param arp_current the arp_cache of the destination
 * @param msg         the payload
 * @param length      lenght of the payload
 * @param ttl         Time to live, how many times the message can be forwarded before it is discarded
 */
void send_transport_message(struct arp_cache* arp_current, unsigned char* msg, int length, int ttl) {
  struct mip_frame2* mip_ramme2;
  struct ethernet_frame* eth_ramme;
  size_t mip_size2 = sizeof(struct mip_frame2) + length;

  if (mip_size2 > 1500) {

    printf("MIP_PACKAGE EXCEEDS 1500 BYTE %zd\nMESSAGE DISCARDED\n", mip_size2);
    return;
  }

  printf("this is the length u  garbage %d\n", length / 4 );

  mip_ramme2 = malloc(mip_size2);

  mip_ramme2->header = create_mip_header(4,arp_current->mip_dst, arp_current->mip_src,length / 4,ttl);
  memcpy(mip_ramme2->content, msg, length);
  size_t msg_size = sizeof(struct ethernet_frame) + mip_size2;
  eth_ramme = malloc (msg_size);
  memcpy(eth_ramme->destination, arp_current->dst_mac, 6);
  memcpy(eth_ramme->source, arp_current->src_mac, 6);
  eth_ramme->protocol=htons(ETH_P_MIP);
  memcpy(eth_ramme->msg, mip_ramme2, mip_size2);
  ssize_t ret = send(arp_current->fd, eth_ramme, msg_size, 0);



  printf("this is the header %u  %d \n", mip_ramme2->header, LENGTH);

  if (ret == -1 ) {
    perror("epoll_event: transport");
    return;
  }

  if (debug) {
    printf("TRA: %d ",mip_ramme2->header >> (TRA));
    printf("SRC MIP: %d ",mip_ramme2->header >> (SRC) & 255);
    printf("LEN: %d ", (mip_ramme2->header >> (LENGTH) & 511));
    printf("DST MIP: %d ", mip_ramme2->header >> (DST) & 255);
    printf("TTL: %d",mip_ramme2->header >> (TTLS) & 15);
    printf("\n");
  }

  free(eth_ramme);
  free(mip_ramme2);

  return;
}


/**
 * this method sends a message without payload, it is used when the daemon sends an arp_request/arp_response
 * @param  tra         TRA = 0 arp_response. TRA = 1 arp request
 * @param  arp_current [the arp_cache]
 * @param  mip_addr    [the mip_adress destination]
 */
void send_message_wo_payload(uint8_t tra, struct arp_cache* arp_current, unsigned char mip_addr) {
  struct ethernet_frame* eth_ramme;
  struct mip_frame2* mip_ramme2;
  mip_ramme2 = malloc(sizeof(struct mip_frame2));
  size_t msg_size = sizeof(struct ethernet_frame) + sizeof(struct mip_frame2);
  eth_ramme = malloc (msg_size);
  memcpy(eth_ramme->source, arp_current->src_mac, 6);

  if (tra == 0) {
    mip_ramme2->header = create_mip_header(0, mip_addr, arp_current->mip_src,0,15);
    memcpy(eth_ramme->destination,arp_current->dst_mac,6);
  }
  if (tra == 1) {
    mip_ramme2->header = create_mip_header(1, mip_addr, arp_current->mip_src,0,15);
    memcpy(eth_ramme->destination, broadcast_mac, 6);
  }

  eth_ramme->protocol = htons(ETH_P_MIP);
  memcpy(eth_ramme->msg, mip_ramme2, sizeof(struct mip_frame2));
  ssize_t ret = send(arp_current->fd, eth_ramme, msg_size, 0);

  if (ret == -1) {
    perror("epoll_event(): send()");
    exit(EXIT_FAILURE);
  }



  free(eth_ramme);
  free(mip_ramme2);
}


/**
 * sends routing information recieved from the router to recipient given by the router
 * @param arp_current the arp_cache of the recipient
 * @param buf         a buffer containing the routes,
 * @param length      length of the buffer
 */
void send_unicast(struct arp_cache *arp_current,unsigned char *buf, int length) {
  struct ethernet_frame* eth_ramme;
  struct mip_frame2* mip_ramme2;
  int mip_size2 = sizeof(struct mip_frame2) + length;
  mip_ramme2 = malloc(mip_size2);
  mip_ramme2->header = create_mip_header(2, arp_current->mip_dst,arp_current->mip_src, length / 4, 15);
  memcpy(mip_ramme2->content, buf, length);

  int msg_size = sizeof(struct ethernet_frame) + mip_size2;
  eth_ramme = malloc(msg_size);
  memcpy(eth_ramme->destination, arp_current->dst_mac, 6);
  memcpy(eth_ramme->source, arp_current->src_mac, 6);
  eth_ramme->protocol = htons(ETH_P_MIP);
  memcpy(eth_ramme->msg,mip_ramme2,mip_size2);
  ssize_t ret = send(arp_current->fd, eth_ramme, msg_size, 0);

  ret += ret + 5;
  free(eth_ramme);
  free(mip_ramme2);
}


/**
 * Sends the broadcast of local routes from the routing_server to all neighbours
 * @param buf    buffer containing the local routes
 * @param length length of the buffer
 */
void send_broadcast(unsigned char *buf, int length) {
  struct arp_cache *arp_current = arp_cache_list;

  while (arp_current != NULL) {
    struct mip_frame2* mip_ramme2;

    struct ethernet_frame* eth_ramme;
    int mip_size2 = sizeof(struct mip_frame2) + length;
    mip_ramme2 = malloc(mip_size2);
    mip_ramme2->header = create_mip_header(2, 255,arp_current->mip_src, length / 4, 15);
    memcpy(mip_ramme2->content, buf, length);
    int msg_size = sizeof(struct ethernet_frame) + mip_size2;
    eth_ramme = malloc(msg_size);
    memcpy(eth_ramme->destination, broadcast_mac, 6);
    memcpy(eth_ramme->source, arp_current->src_mac, 6);
    eth_ramme->protocol = htons(ETH_P_MIP);
    memcpy(eth_ramme->msg,mip_ramme2,mip_size2);
    ssize_t ret = send(arp_current->fd, eth_ramme, msg_size, 0);

    ret += ret;

    free(eth_ramme);
    free(mip_ramme2);
    arp_current = arp_current->arp_next;
  }
}


/**
 * creates and returns an accept socket listening to the sockpath argument, exits the program if the socket fails to be created
 * @param  sockpath
 * returns the file descriptor of the newly created socket
 */
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


/**
 * creates up too numbMIPS/(number of ethernet interfaces) RAW sockets to the sent in int array, then adds them to the sent in int array.
 * Tries to assign each mip to a valid ethernet interface. And creates a arp_cache for each socket created. the arp_cache gets assigned a local mac and mip at creation.
 * @param  fds: a pointer to epctrl->eths_fd, which is where the created ethernet sockets are stored
 * returns the number of created sockets.
 */
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


/**
 * adds the sent in socket to the sent in epoll_fd,
 * @param  epctrl    [struct containing the epoll fd]
 * @param  fd        [the fd to be added]
 * @param  listening [checks if the socket is an accept socket or not (1 = true, 0 = false)]
 * @param  family    [the socket family e.g (eth, client, forw, route)]
 */
void epoll_add(struct epoll_control *epctrl, int fd, int listening, char *family)
{
  //NB: HVis du bruker EPOLLET -> så må socket være NONBLOCKING
  if (debug) {
    printf("ADDED AN %s SOCKET WITH SD: %d \n",family, fd );
  }
  struct fdInfo *info = malloc(sizeof(struct fdInfo) + strlen(family) + 1);
  struct epoll_event ev;
  ev.events = EPOLLIN;
  info->listen = listening;
  info->family = family;
  info->fd = fd;
  ev.data.ptr = info;
  if (epoll_ctl(epctrl->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    perror("epoll_add: epoll_ctl()");
    exit(EXIT_FAILURE);
  }
  return;
}


/**
 * handles the client interraction, gets called when client sends us data.
 * reads a mip_addr and a message, and then checks if mip_addr is a know neighbour. if it is a known neighbour it calls send_transport_message(),
 * else it ask the router where it should send message, and stores the message in the route_backlog;
 * @param epctrl [a struct containg all necessary fds]
 * @param info   [the event that triggered epoll_wait]
 */
void handle_client_socket(struct epoll_control *epctrl, struct fdInfo *info) {
  //a new client connected !
  if (info->listen == 1 && epctrl->connected_unix == 0) {
    int connect_sock = 0;
    struct sockaddr_un sockaddr = {0};
    sockaddr.sun_family = AF_UNIX;
    socklen_t addrlen = sizeof(sockaddr);
    connect_sock = accept(epctrl->client_fd, (struct sockaddr *)&sockaddr, &addrlen);

    if (connect_sock == -1) {
      perror("epoll_event: accept()");
      exit(EXIT_FAILURE);
    }

    epctrl->connected_unix = connect_sock;
    epoll_add(epctrl, connect_sock, 0, "client");
    if (debug) {
      fprintf(stdout, "NEW UNIX CONNECTION ESTABLISHED\n");
    }
  }

  //a connected client sent a message
  else {
    unsigned char buf[BUF_SIZE] = {0};
    ssize_t ret = recv(epctrl->connected_unix, buf,sizeof(buf), 0);
    if (debug) {
      fprintf(stdout, "RECV %ld BYTES FROM CLIENT\n", ret);
    }

    if (ret == 0) {
      close(epctrl->connected_unix);
      epctrl->connected_unix = 0;
      if (debug) {
        fprintf(stdout, "UNIX CONNECTION CLOSED\n");
      }
      return;
    }

    if (ret == -1) {
      perror("epoll_event: recv()");
      close(epctrl->connected_unix);
      epctrl->connected_unix = 0;
      return;
    }

    unsigned char *msg = malloc(ret - 1);
    unsigned char mip_addr = buf[0];
    memcpy(msg, buf + 1, ret - 1);
    //checks if the mip_addr is a known local neighbour or not
    struct arp_cache* arp_dest = dst_in_arp_cache(mip_addr);
    if (arp_dest == NULL) {
      //not a know neighbour, therefore we have to ask the router for next_jump
      if (epctrl->connected_forward == 0) {
        if (debug) {
          printf("NO ROUTER CONNECTED, PACKAGE DROPPED\n");
        }
        return;
      }

      unsigned char dst = mip_addr;
      ssize_t ret3 = send(epctrl->connected_forward, &dst, sizeof(dst),0);

      if (ret3 <= 0) {
        close(epctrl->connected_forward);
        close(epctrl->connected_router);
        epctrl->connected_router = 0;
        epctrl->connected_forward = 0;

        if (debug) {
          printf("SEND FAILED, DISCONNECTED ROUTER\n");
        }
        return;
      }

      if (debug) {
        printf("ROUTE LOOK UP SENTs\n");
      }

      struct route_backlog *route_temp = malloc(sizeof(struct route_backlog) + ret - 1);
      route_temp->mip = mip_addr;
      route_temp->from = 0;
      route_temp->length = ret - 1;
      route_temp->ttl = 15;
      route_temp->msg_next = NULL;
      memcpy(route_temp->msg, msg, route_temp->length);
      add_to_route_backlog(route_temp);
    }

    //it was a known local neighbour
    else {

      printf("ret from mipdt %zd \n", ret - 1);

      send_transport_message(arp_dest, msg, ret - 1, 15);
    }
  }
  return;
}


/**
 * Handles the ehternet sock interaction, gets triggered when we recieve a message from other daemons.
 * Does 4 different things depending on what tra is.
 * If TRA is set to 0, it updates the arp_cache with the content of package
 * if TRA is set to 1, it updates the arp_cache with the contet of package, and the send out a ARP_RESPONSE
 * if TRA is set to 2, it sends the message to its router
 * if TRA is set to 4, it checks if it is a message to itself, if it is it sends the message to client, else it ask the router where it should forward the message
 * @param epctrl [a struct containg all necessary fds]
 * @param info   [the event that triggered epoll_wait]
 */
void handle_ethernet_socket(struct epoll_control *epctrl, struct fdInfo *info) {
  unsigned char buf[BUF_SIZE];
  ssize_t ret = recv(info->fd, buf, sizeof(buf),0);
  struct ethernet_frame* eth_ramme = (struct ethernet_frame*) buf;
  struct mip_frame2* mip_ramme2 = (struct mip_frame2*) eth_ramme->msg;
  if (debug) {
    printf("ETH_MSG OF %zd RECV: ", ret);
    printf("TRA: %d ",mip_ramme2->header >> (TRA));
    printf("SRC MIP: %d ",mip_ramme2->header >> (SRC) & 255);
    printf("LEN: %d ", (mip_ramme2->header >> (LENGTH) & 511));
    printf("DST MIP: %d ", mip_ramme2->header >> (DST) & 255);
    printf("TTL: %d",mip_ramme2->header >> (TTLS) & 15);
    printf("\n");
  }
  struct arp_cache* arp_current;

  //ARP_REQUEST RECIEVED
  if ((mip_ramme2->header >> (TRA)) == 1) {
    arp_current = src_in_arp_cache(mip_ramme2->header >> (DST) & 255);
    if (arp_current == NULL) {
      return;
    }

    if (arp_current->fd != info->fd) {
      printf("correct mip but wrong socket %d %d\n", arp_current->fd, info->fd );
      return;
    }

    if (arp_current->mip_dst == 0) {
      arp_current->mip_dst = mip_ramme2->header >> (SRC) & 255;
      memcpy(arp_current->dst_mac, eth_ramme->source,6);
    }

    send_message_wo_payload(0, arp_current, arp_current->mip_dst);
    return;
  }//ARP_REQUEST ENDS


  //ROUTING MESSAGE RECIEVED
  else if ((mip_ramme2->header >> (TRA)) == 2) {

    if (epctrl->connected_router == 0) {
      if (debug) {
        printf("NO ROUTER CONNECTED, PACKAGE DROPPED\n");
        return;
      }
    }

    unsigned char routing_info[BUF_SIZE];
    routing_info[0] = mip_ramme2->header >> (SRC) & 255;
    memcpy(routing_info + 1, mip_ramme2->content, ret - (sizeof(struct ethernet_frame) + sizeof(struct mip_frame2)));
    ssize_t ret2 = send(epctrl->connected_router, routing_info, ret - (sizeof(struct ethernet_frame) + sizeof(struct mip_frame2) - 1), 0);

    if (debug) {
      printf("SENT %zd BYTES TO ROUTER\n",ret2);
    }

    return;
  }//ROUTING ENDS


  //TRANSPORTING MESSAGE RECIEVED
  else if ((mip_ramme2->header >> (TRA)) == 4) {
    //recieved message to myself!
    if (src_in_arp_cache(mip_ramme2->header >> (DST) & 255) != NULL) {
      if (epctrl->connected_unix == 0) {
        if (debug) {
          printf("NO LOCAL APPLICATIONS CONNECTED\nMESSAGE DISCARDED\n");
        }
        return;
      }

      unsigned char buf[BUF_SIZE] = {0};
      unsigned char mip_addr = mip_ramme2->header >> (SRC) & 255;
      buf[0] = mip_addr;
      memcpy(buf + 1, &mip_ramme2->content, (mip_ramme2->header >> (LENGTH) & 511) * 4);
      ssize_t ret = send(epctrl->connected_unix,buf,sizeof(mip_addr) + (mip_ramme2->header >> (LENGTH) & 511) * 4, 0);

      if(ret == -1) {
        close(epctrl->connected_unix);
        epctrl->connected_unix = 0;
        return;
      }
      if (debug) {
        fprintf(stdout, "SENT %ld BYTES TO CLIENT VIA UNIX \n", ret);
      }
      return;
    }

    else {

      if ((mip_ramme2->header >> (TTLS) & 15) == 0) {
        if (debug) {
          printf("TTL = 0, MESSAGE DISCARDED\n");
        }
        return;
      }

      if (epctrl->connected_forward == 0) {
        if (debug) {
          printf("NO ROUTER CONNECTED, PACKAGE DROPPED\n");
        }
        return;
      }
      unsigned char dst = mip_ramme2->header >> (DST) & 255;
      ssize_t ret3 = send(epctrl->connected_forward, &dst, sizeof(dst),0);

      if (ret3 <= 0) {
        close(epctrl->connected_forward);
        close(epctrl->connected_router);
        epctrl->connected_router = 0;
        epctrl->connected_forward = 0;

        if (debug) {
          printf("SEND FAILED, DISCONNECTED ROUTER\n");
        }
        return;
      }

      if (debug) {
        printf("ROUTE LOOK UP SENT\n");
      }

      struct route_backlog *msg = malloc(sizeof(struct route_backlog) + (mip_ramme2->header >> (LENGTH) & 511) * 4);
      msg->mip = mip_ramme2->header >> (DST) & 255;
      msg->from = mip_ramme2->header >> (SRC) & 255;
      msg->length = (mip_ramme2->header >> (LENGTH) & 511) * 4;
      msg->ttl = (mip_ramme2->header >> (TTLS) & 15) - 1;
      msg->msg_next = NULL;
      memcpy(msg->msg, mip_ramme2->content, msg->length);
      add_to_route_backlog(msg);
      return;
    }
  }//TRANSPORT ENDS


  //ARP_RESPONSE RECIEVED
  else if ((mip_ramme2->header >> (TRA) & 7) == 0) {

    if (debug) {
      printf("RECIEVED ARP RESPONE, ARP_CACHE TABLE UPDATED\n");
    }

    arp_current = src_in_arp_cache(mip_ramme2->header >> (DST) & 255);
    if (arp_current == NULL) {
      return;
    }

    if (arp_current->mip_dst == 0) {
      arp_current->mip_dst = mip_ramme2->header >> (SRC) & 255;
      memcpy(arp_current->dst_mac, eth_ramme->source,6);
    }

    //checks the backlog to see if we can now send some of the stored messages
    struct arp_backlog* msg_current = get_msg_with_dst(arp_current->mip_dst);
    while (msg_current != NULL) {
      if (msg_current->tra == 4) {
        send_transport_message(arp_current, msg_current->msg, ret - 1,15);
      }
      else if (msg_current->tra == 2) {
        send_unicast(arp_current, msg_current->msg, msg_current->length);
      }
      msg_current = get_msg_with_dst(arp_current->mip_dst);
    }
    return;
  }//ARP RESPONSE ENDS

  return;
}


/**
 * Handles the forward sokcet, gets the next jump from the router, and then gets the oldest message from the route_backlog and attempts to forward that message.
 * @param epctrl [a struct containg all necessary fds]
 * @param info   [the event that triggered epoll_wait]
 */
void handle_forwarding_socket(struct epoll_control *epctrl, struct fdInfo *info) {
  if (info->listen == 1 && epctrl->connected_forward == 0) {
    int connect_sock;
    struct sockaddr_un sockaddr = {0};
    sockaddr.sun_family = AF_UNIX;
    socklen_t addrlen = sizeof(sockaddr);

    connect_sock = accept(epctrl->forw_fd, (struct sockaddr *)&sockaddr, &addrlen);
    if (connect_sock == -1) {
      perror("epoll_event: accept()");
      exit(EXIT_FAILURE);
    }

    epctrl->connected_forward = connect_sock;
    epoll_add(epctrl, connect_sock, 0, "forwarding");
    return;
  }

  else {

    unsigned char buf[BUF_SIZE] = {0};
    unsigned char next_jump = 0;
    ssize_t ret = recv(epctrl->connected_forward, buf, BUF_SIZE, 0);
    next_jump = buf[0];

    if (ret <= 0) {
      return;
    }

    struct route_backlog *route_temp = NULL;
    if (next_jump == 255 || next_jump == 0) {
      route_temp = get_msg_from_route_log();
      if (route_temp != NULL) {
        free(route_temp);
      }
      return;
    }

    else {
      route_temp = get_msg_from_route_log();

      if (route_temp == NULL) {
        printf("burde ikke skje\n");
        return;
      }

      struct arp_cache *arp_temp = dst_in_arp_cache(next_jump);

      if (arp_temp == NULL) {
        printf("skjer dettte???\n");
        //this should never happen since a router can't give us a next_jump we dont know about;
        return;
      }
      forward_message(arp_temp, route_temp);
      free(route_temp);

      if (debug) {
        printf("SUCCESSFULLY FORWARDED TO %d \n",next_jump);
      }
      return;
    }
  }
}


/**
 * Handles the routing socket, when a new routing socket connects, it sends all the local mips to the routing socket.
 * When it recvs from the routing socket, it checks if it is a uni- or broadcast, if it is a broadcast, then it sends out the routing info to all neighbours, regardless if they are knonw or not.
 * if it is a unicast, it checks if the neighbour is known, if the neighbour is know it sends out the unicast.
 * if the neighbour isn't know then it has to send out an arp_response and store the routing informatin in the arp_backlog.
 * it will never (read: should) recieve unicast to someone who is not an neighbour, but if it does, the message will just be stored in the backlog forever.
 * @param epctrl [a struct containg all necessary fds]
 * @param info   [the event that triggered epoll_wait]
 */
void handle_router_socket(struct epoll_control *epctrl, struct fdInfo *info) {
  if (info->listen == 1 && epctrl->connected_router == 0) {
    int connect_sock = 0;
    struct sockaddr_un sockaddr = {0};
    sockaddr.sun_family = AF_UNIX;
    socklen_t addrlen = sizeof(sockaddr);
    connect_sock = accept(epctrl->rout_fd, (struct sockaddr *)&sockaddr, &addrlen);

    if (connect_sock == -1) {
      perror("epoll_event: accept()");
      exit(EXIT_FAILURE);
    }

    epctrl->connected_router = connect_sock;
    epoll_add(epctrl, epctrl->connected_router, 0, "router");
    if (debug) {
      fprintf(stdout, "ROUTER CONNECTED\n");
    }

    unsigned char msg[BUF_SIZE] = {0};
    unsigned int count = 1;
    struct arp_cache *arp_current = arp_cache_list;
    msg[0] = 255;
    while (arp_current != NULL) {
      msg[count] = arp_current->mip_src;
      count++;
      msg[count] = 0;
      count++;
      msg[count] = arp_current->mip_src;
      count++;
      arp_current = arp_current->arp_next;
    }


    while ((count - 1) % 4 != 0) {
      msg[count] = 255;
      count++;
    }

    ssize_t ret = send(epctrl->connected_router, msg, count, 0);
    if (ret == -1) {
      printf("Failed to send local mipts to router\n");
      close(epctrl->connected_router);
      close(epctrl->connected_forward);
      epctrl->connected_router = 0;
      epctrl->connected_forward = 0;
      return;
    }

    if (ret == 0) {
      printf("ROUTING_SERVER DISCONNECTED\n");
      close(epctrl->connected_router);
      close(epctrl->connected_forward);
      epctrl->connected_router = 0;
      epctrl->connected_forward = 0;
      return;
    }

    return;
  }

    unsigned char buf[BUF_SIZE] = {0};
    ssize_t ret = recv(epctrl->connected_router, buf, sizeof(buf),0);

    if (ret == -1) {
      printf("Failed to read from router_SOCKET\n");
      close(epctrl->connected_router);
      close(epctrl->connected_forward);
      epctrl->connected_router = 0;
      epctrl->connected_forward = 0;
      return;
    }

    if (ret == 0) {
      printf("ROUTING_SERVER DISCONNECTED\n");
      close(epctrl->connected_router);
      close(epctrl->connected_forward);
      epctrl->connected_router = 0;
      epctrl->connected_forward = 0;
      return;
    }

    unsigned char msg[ret - 1];
    memcpy(msg, buf + 1, ret - 1);
    //broadcast routes

    if (buf[0] == 255) {
      send_broadcast(msg, ret - 1);
    }

    //unicast
    else {

      if (debug) {
        printf("RECIEVED UNICAST TO %d OF %zd BYTES\n", buf[0], ret);
      }
      unsigned char dst = buf[0];
      struct arp_cache *arp_dest = dst_in_arp_cache(dst);

      if (arp_dest == NULL) {
        //sending out an arp_request
        struct arp_cache* arp_current = arp_cache_list;
        if (arp_current == NULL) {
          if (debug) {
            printf("NO VALID INTERFACES\n MESSAGE DISCARDED\n");
          }
          return;
        }

        while (arp_current != NULL) {

          if (arp_current->mip_dst == 0) {
            send_message_wo_payload(1,arp_current, dst);
          }
          arp_current = arp_current->arp_next;
        }

        struct arp_backlog* msg_temp = malloc(sizeof(struct arp_backlog) + ret - 1);
        msg_temp->mip_dst = dst;
        msg_temp->tra = 2;
        msg_temp->length = ret - 1;
        msg_temp->msg_next = NULL;
        memcpy(msg_temp->msg, msg, ret - 1);
        add_to_arp_backlog(msg_temp);
      }

      //arp lookup found the dest;
      else {
        send_unicast(arp_dest, msg, ret - 1);
      }
    }
}


/**
 * sends the event further down, to another method which parses and handles the event.
 * @param  epctrl [an struct which contains information about the sockets, and the epoll fd)]
 * @param  n      [index of which event we are handling know]
 */
void epoll_event(struct epoll_control *epctrl, int n)
{
  struct fdInfo *info = epctrl->events[n].data.ptr;

  if (strcmp(info->family, "client") == 0 ) {
    handle_client_socket(epctrl, info);
  }

  else if (strcmp(info->family, "ethernet") == 0) {
    handle_ethernet_socket(epctrl, info);
  }

  else if (strcmp(info->family, "forwarding") == 0) {
    handle_forwarding_socket(epctrl, info);
  }

  else if (strcmp(info->family, "router") == 0) {
    handle_router_socket(epctrl,info);
  }

  else {
    printf("Unexpected socket behaviour! This should never happen!\n");
  }
}

/**
 * [sets up the unix socket and ethernets sockets, creates and start a epoll with the fds. And then calls epoll_wait in a neverending loop]
 * @param  argc [number of arguments from user]
 * @param  argv [the arguments]
 *
 */
int main(int argc, char* argv[]) {
  if (argc < 5) {
    printf(RED "usage: [-h] [-d] <socket_applictaion> <Socket_router> <socket_forwarding> [mip_addresses]\n" RESET );
    exit(0);
  }

  char* sockpath1, *sockpath2, *sockpath3;

  if (strcmp (argv[1],  "-h") == 0) {
    printf("commands:\n"
    "Normal: <socket_applictaion> <Socket_router> <socket_forwarding> [mip_addresses]\n"
    "debug mode: -d <socket_applictaion> <Socket_router> <socket_forwarding> [mip_addresses]\n");
    exit(0);
  }

else if (strcmp(argv[1], "-d") == 0) {
    debug = 1;
    printf(GRN "DEBUG MODE ENABLED\n" RESET);
    sockpath1 = argv[2];
    sockpath2 = argv[3];
    sockpath3 = argv[4];

    numbMIPS = argc - 5;

    for(int i = 0; i < argc - 5; i++) {
      mips[i] = atoi(argv[i + 5]);
    }
  }

  else {
    numbMIPS = argc - 4;
    sockpath1 = argv[1];
    sockpath2 = argv[2];
    sockpath3 = argv[3];

    for(int i = 0; i < argc - 4; i++) {
      mips[i] = atoi(argv[i + 4]);
    }
  }

  printf(CYN"MIP DAEMON STARTED\n" RESET );
  struct epoll_control epctrl;
  epctrl.epoll_fd = epoll_create(99);
  epctrl.connected_unix = 0;
  epctrl.connected_router = 0;
  epctrl.connected_forward = 0;

  if (epctrl.epoll_fd == -1) {
    perror("main: epoll_create()");
    exit(EXIT_FAILURE);
  }

  epctrl.client_fd = setup_unix_socket(sockpath1);
  epctrl.rout_fd = setup_unix_socket(sockpath2);
  epctrl.forw_fd = setup_unix_socket(sockpath3);

  epoll_add(&epctrl, epctrl.client_fd, 1 , "client");
  epoll_add(&epctrl, epctrl.rout_fd, 1, "router");
  epoll_add(&epctrl, epctrl.forw_fd, 1, "forwarding");

  memset(epctrl.eths_fd,0,sizeof(epctrl.eths_fd));
  int ethsocks_created = setup_ethernet_socks(epctrl.eths_fd);

  if (debug) {
    printf("CREATED %d EHTERNET SOCKETS\n",ethsocks_created);
  }

  for (int i = 0; i < ethsocks_created; i++) {
    epoll_add(&epctrl, epctrl.eths_fd[i], 1 , "ethernet");
  }

  printf( "SET-UP FINISHED\n" RESET);
  //TODO: add updates every X seconds
  for(;;) {
    int nfds, n;
    nfds = epoll_wait(epctrl.epoll_fd, epctrl.events, MAX_EVENTS, 0);

    if (nfds == -1) {
      perror("main: epoll_wait");
      exit(EXIT_FAILURE);
    }

    for (n = 0; n < nfds; n++) {
      epoll_event(&epctrl, n);
    }
  }
}
