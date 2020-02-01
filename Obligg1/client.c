#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  if (argc != 3) {
    fprintf(stderr, "USAGE: %s [interface_name] [msg]", argv[0]);
    exit(EXIT_FAILURE);
  }

    char *interface = argv[1];
    uint8_t mac[6];
    int protocol = htons(ETH_P_ALL);
    int sock = socket(AF_PACKET, SOCK_RAW, protocol);

    get_mac_addr(sock, mac, interface);
    print_mac(mac);

    struct sockaddr_ll sockaddr = { 0 };
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_ifindex = if_nametoindex(interface);
    printf("NAME TO INDEX: %d\n", sockaddr.sll_ifindex);

    if (bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1) {
      perror("main: bind()");
      exit(EXIT_FAILURE);
    }

    size_t msg_size = sizeof(struct ethernet_frame) + strlen(argv[2]);
    struct ethernet_frame *ramme = malloc(msg_size);

    memcpy(ramme->source, mac, sizeof(mac));
    memcpy(ramme->destination, "\xff\xff\xff\xff\xff\xff", 6);
    //ramme->protocol = htons(0);
    ramme->protocol = htons(ETH_P_ALL);
    memcpy(ramme->msg, argv[2], strlen(argv[2]));

    dump_frame(ramme);
    int ret = send(sock, ramme, msg_size, 0);
    if (ret == -1) {
      perror("main: send()");
      exit(EXIT_FAILURE);
    }
    fprintf(stdout, "Antall bytes: %d\n", ret);
    close(sock);
    free(ramme);



    return 0;
}
