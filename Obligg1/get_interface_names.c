//All kode er skrevet at hansjny, tidligere gruppelærer i INF3190

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>


/** This function lets us grab the name
 * of all the interfaces, and decide which
 * we want to use.
 * ifaddr the struct for retrieving names
 * returns -1 upon failure, 0 if success. */
int getinterfaces(struct ifaddrs *ifaddr) {

	char *filnavn = "socket.sock";
	unlink(filnavn);

	//struct ifaddrs *ifaddr;
	if (getifaddrs(&ifaddr) == -1) {
		perror("Getifaddrs()");
		exit(EXIT_FAILURE);
	}

	struct ifaddrs *ifstart = ifaddr;
	while (ifaddr != NULL) {
		fprintf(stderr, "Interface: %s:", ifaddr->ifa_name);

		struct sockaddr *addr = ifaddr->ifa_addr;
		//hei dette er en switch den gjør så vi kan bestemme hva slags interface vi har
		switch (addr->sa_family) {
			// dette er hvis vi har af_inet
			case AF_INET:
				fprintf(stderr, "ipv4\n");
				break;
			case AF_INET6:
				fprintf(stderr, "ipv6\n");
				break;
			case AF_PACKET:
				fprintf(stderr, "raw\n");
				break;
		}
		ifaddr = ifaddr->ifa_next;
	}
	freeifaddrs(ifstart);
	return 0;
}
