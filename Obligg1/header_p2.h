#ifndef __HEADER_P2
#define __HEADER_P2
#include <inttypes.h>

struct ethernet_frame {
  char destination[6];
  char source[6];
  uint16_t protocol;
  char msg[];
} __attribute__((packed));
#endif
