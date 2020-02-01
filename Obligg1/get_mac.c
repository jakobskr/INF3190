#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include "header_p2.h"

int get_mac_addr (int sock, uint8_t mac[6], char* interface_name)
{
  struct ifreq dev;

  strcpy(dev.ifr_name, interface_name);

  if( ioctl(sock, SIOCGIFHWADDR, &dev) == -1 ) {
    perror("get_mac_addr: ioctl()");
    exit(EXIT_FAILURE);
  }

  memcpy(mac, dev.ifr_hwaddr.sa_data, 6);
  return 0;
}

void print_mac(uint8_t mac[6])
{
  for (int i = 0; i < 5; i++) {
    //printf()
    //fprintf(stderr)
    fprintf(stdout, "%x:", mac[i]);
  }
  fprintf(stdout, "%x\n", mac[5]);
}

void dump_frame(struct ethernet_frame *ramme)
{
  fprintf(stdout, "Source MAC address:\n");
  print_mac(ramme->source);
  fprintf(stdout, "Destination\n");
  print_mac(ramme->destination);
  fprintf(stdout, "Protocol\n");
  fprintf(stdout, "%d\n", ramme->protocol);
  fprintf(stdout, "%s\n", ramme->msg);
}
