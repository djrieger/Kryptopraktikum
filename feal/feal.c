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
            if (j % 2 == 0)
              printf(" ");
        }
    }
    //puts("");
}


ubyte test(ubyte u, ubyte v, int *keyoverflow) {
  ubyte w = rotr(Feal_GS(u, v, keyoverflow));
  printf("u %d v %d w %d (", u, v, w);
  printBits(sizeof(w), &w);
  printf(") overflow %d\n", *keyoverflow);
  return w;
}

int isBitSet(ubyte u, int bitPos)
{
  return (u & (1 << bitPos)) > 0;
}

int findBitWithValue(ubyte number[4], int bitPos, int bitValue) {
  int i;
  for (i = 0; i < 4; i++) {
    if (isBitSet(number[i], bitPos) == bitValue) {
      return i;
    }
  }
  return -1;
}

int findSpecialBit(ubyte number[4], int bitPos, int *bitValue) {
  int index, i;
  int bitCount = 0;
  // sum last but one column
  for (i = 0; i < 4; i++) {
    bitCount += isBitSet(number[i], bitPos);
  }
  if (bitCount == 3) {
    index = findBitWithValue(number, bitPos, 0);
  } else if (bitCount == 1) {
    index = findBitWithValue(number, bitPos, 1);
  } else {
    printf("ERRROR\n");
  }
  *bitValue = isBitSet(number[index], bitPos);
  return index;
}

void setBit(ubyte *number, int bitPosition)
{
  *number = *number | 1 << bitPosition;
}

void test2() {
  ubyte k1,k2,k3;
  k1 = 0;
  k2 = 0;
  k3 = 0;
  int keyoverflow, bitPos;
  ubyte w[4];

  w[0] = test(0, 0, &keyoverflow);
  w[1] = test(1, 0, &keyoverflow);
  w[2] = test(0, 1, &keyoverflow);
  w[3] = test(1, 1, &keyoverflow);

  for (bitPos = 0; bitPos <= 6; bitPos++) {
    int specialBitValue;
    int specialBit = findSpecialBit(w, bitPos, &specialBitValue);
    printf("special at %d, value %d\n", specialBit, specialBitValue);

     switch (specialBit) 
     {
        case 0: setBit(&k1, bitPos); setBit(&k2, bitPos); break;
        case 1: setBit(&k2, bitPos); break;
        case 2: setBit(&k1, bitPos); break;
        case 3:  break;
        default: printf("ERROR\n");
     }
   }

  printBits(sizeof(k1), &k1);
  printf("\n");
  printBits(sizeof(k2), &k2);
}

int main(int argc, char **argv)
{
  ubyte k1,k2,k3;
  Feal_NewKey();
  test2();

  /*>>>>                                                      <<<<*/
  /*>>>>  Aufgabe: Bestimmen der geheimen Schlüssel k1,k2,k3  <<<<*/
  /*>>>>                                                      <<<<*/
  printf("Lösung: $%02x $%02x $%02x: %s",k1,k2,k3, Feal_CheckKey(k1,k2,k3)?"OK!":"falsch" );
  return 0;
}







