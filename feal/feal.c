/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 4: Brechen der Blockchiffre FEAL                  *
**                                                           *
**************************************************************
**
** feal.h Headerfile für den Feal-Versuch
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "feal.h"

static ubyte rotr(ubyte a)
  {
    return ( (a>>2) | (a<<6) ) & 0xff;
  }

static ubyte calc_f(ubyte u, ubyte v)
  {
    int overflow;
    ubyte r;

    r=Feal_GS(u,v,&overflow);
    if (overflow) {
      fprintf(stderr,"FEHLER: Schlüssel-Überlauf, u=%02x, v=%02x\n",u,v);
      exit(20);
    }

    return r;
  }

/* --------------------------------------------------------------------------- */


//assumes little endian
void printBits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--)
    {
        for (j=7;j>=0;j--)
        {
            byte = b[i] & (1<<j);
            byte >>= j;
            printf("%u", byte);
        }
    }
    puts("");
}


void test(ubyte u, ubyte v, int *keyoverflow) {
  ubyte w = Feal_GS(u, v, keyoverflow);
  printf("u %d v %d w %d (", u, v, w);
  printBits(sizeof(w), &w);
  printf(")\n");
}

int main(int argc, char **argv)
{
  ubyte k1,k2,k3;
  Feal_NewKey();
  int keyoverflow;
  test(0, 0, &keyoverflow);
  test(1, 0, &keyoverflow);
  test(0, 1, &keyoverflow);
  test(1, 1, &keyoverflow);
  /*>>>>                                                      <<<<*/
  /*>>>>  Aufgabe: Bestimmen der geheimen Schlüssel k1,k2,k3  <<<<*/
  /*>>>>                                                      <<<<*/
  printf("Lösung: $%02x $%02x $%02x: %s",k1,k2,k3, Feal_CheckKey(k1,k2,k3)?"OK!":"falsch" );
  return 0;
}







