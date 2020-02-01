#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Slik oppretter man en struct */
struct element {
  int nummer;
  char bokstav;
  /* kan ha flere variabler, pekere og arrays her. MEN IKKE FUNKSJONER! */

  char data[];
};

int main(void) {
  //Enten opprette en strukt på stacken, da vil char data[] være en enkel peker, kan ikke ha flexible array strukt
  struct element strukten_min;
  strukten_min.nummer = 1;

  /* Eller opprette på HEAP, Dynamisk minne, da kan du lage struckter med "flexible arrays" */
  struct element *e = malloc(sizeof(struct element) + 22);
  /** Må bruke -> for å nå data til en peker i strukten, når du har en peker til strukten.
  * Se link for forklaring: https://stackoverflow.com/questions/5998599/difference-between-and-in-a-struct
  * e->data er det samme som: (*e).data;
  */

  //kopierer inn ett ord inn i data
  memcpy(e->data, "velkommen til inf3190", 22);
  printf("%s\n", e->data);
  /* ALLTID HUSK Å FREE!!! */
  free(e);

  return 0;
}
