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


int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <interface name>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Velger hvilken protokoll vi skal bruke. ETH_P_ALL er ALLE protokoller som den kan bruke */
  int protocol = htons(ETH_P_ALL);
  /* Oppretter en RAW socket. Se man 2 socket og man 7 packet */
  int sock = socket(AF_PACKET, SOCK_RAW, protocol);

  /* Sjekk return value til funksjonen. Kan det oppstå en ERROR? */
  if (sock == -1) {
    perror("main(): socket()");
    exit(EXIT_FAILURE);
  }

  uint8_t mac[6];

  /* nullsetter strukten, slik at søppel info fra tidligere ikke er i strukten vår
   * Kan bruke = {0} eller funksjonen memset()
   * = {0} vil gjøre at du får en ERROR msg noen ganger, men det er en bug.
   * For å unngå å få feilmeldinger bruk memset(), som vist under, istedetfor
   */
  //struct ifreq interface_info = {0};

  struct ifreq interface_info;
  memset(&interface_info, 0, sizeof(interface_info));
  /** Bruke denne måten for å unngå feilmeldinger under kompilering. Begge måter er OK.
  */

  /* Kopierer over interface name, til strukten */
  strcpy(interface_info.ifr_name, argv[1]);
  /* Bruker ioctl() til å hente hardware info fra interface name */
  if ( ioctl(sock, SIOCGIFHWADDR, &interface_info) == -1) {
    //error handling
    perror("main(): ioctl()");
    exit(EXIT_FAILURE);
  }

  /* Data ligger i interface_info.ifr_hwaddr.sa_data.
  Det står i manpages at hardware adressen blir lagret i en struct ifr_hwaddr og den vil ha en data type som heter: "sa_data"
  L2 = Layer 2 = Link layer.
  Se man 7 netdevice eller https://linux.die.net/man/7/netdevice:
  SIOCGIFHWADDR, SIOCSIFHWADDR
  Get or set the hardware address of a device using ifr_hwaddr. The hardware address is specified in a
  struct sockaddr. sa_family contains the ARPHRD_* device type, sa_data the L2 hardware address starting from byte 0.
  Setting the hardware address is a privileged operation.
  */

  memcpy(mac, interface_info.ifr_hwaddr.sa_data, sizeof(mac));

  //Printer ut mac adressen. Printer ut
  for (int i = 0; i < 5; i++) {
    printf("%x", mac[i]);
  }
  printf("%x\n", mac[5]);

  #ifdef TEST_PRINT1
  int a = 5;
  printf("Skrives alltid ut med 2 tall: %02d\n", a);
  printf("Skrives alltid ut med 5 tall: %05d\n", a);
  #elif TEST_PRINT2
  double b = 22.5;
  printf("Skrives ut med 3 tall etter komma: %.3f\n", b);
  printf("Skrives ut med plass til 10 før og 3 tall etter komma: %10.3f\n", b);
  #endif

  return 0;


}
