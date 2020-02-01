#include <stdlib.h>

#include <stdio.h>

#include <string.h>

#include <unistd.h>

#include <inttypes.h>


int main(void) {
  uint32_t test = 0;
  test ^= (-4 ^ test) & (4 << 32 - 3);
  test ^= (-255 ^ test) & (255 << 32 - 3 - 8);
  test ^= (-40 ^ test) & (70 << 32 - 3 - 8 - 8);
  test ^= (-240 ^ test) & (240 << 32 - 3 - 8 - 8 - 9);
  test |= 15;

  printf("%x \n",test );
  printf("%d\n", (test >> 32 - 3 - 8 - 8 - 9 - 4) & 15);
}
