#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "header_p2.h"
#include "get_mac.c"
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
       #include <sys/socket.h>
       #include <linux/if_packet.h>
       #include <net/ethernet.h>
#include <net/if.h>
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>
#include <unistd.h>

#define ETH_P_EXP 0x88B5

int main(int argc, char* argv[])
{
  if(argc != 2) {
    fprintf(stderr, "USAGE: %s [interface_name]\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  char *interface = argv[1];
  uint8_t mac[6];
  int protocol = htons(ETH_P_ALL);
  int sock = socket(AF_PACKET, SOCK_RAW, protocol);

  if (sock == -1) {
    printf("ULU OLOY\n");
  }
  get_mac_addr(sock, mac, interface);
  print_mac(mac);

  struct sockaddr_ll sockaddr = { 0 };
  //struct sockaddr_ll sockaddr;
  //memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sll_family = AF_PACKET;
  sockaddr.sll_protocol = htons(ETH_P_ALL);
  sockaddr.sll_ifindex = if_nametoindex(interface);

  if (bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1) {
    perror("main: bind()");
    exit(EXIT_FAILURE);
  }

  for (;;) {
    char buf[1500];
    recv(sock, buf, sizeof(buf), 0);
    struct ethernet_frame *ramme = (struct ethernet_frame*) buf;
    dump_frame(ramme);
    fprintf(stdout, "RAMME er mottatt!!!\n");
  }

  close(sock);

  return 0;
}
