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
/*
 * Gibt die Binärdarstellung von *ptr aus
 *
 * @param highlightPos  Position des Bits, das in der Binärdarstellung rot
 *                      ausgegeben werden soll
 */
void printBits(size_t const size, void const * const ptr, int highlightPos)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1; i>=0; i--)
    {
        for (j=7; j>=0; j--)
        {
            byte = b[i] & (1<<j);
            byte >>= j;
            if (j == highlightPos) printf("\033[31m");
            printf("%u", byte);
            if (j == highlightPos) printf("\033[0m");
            if (j % 2 == 0)
                printf(" ");
        }
    }
}

/*
 * Berechne w = G'(u, v) und gibt u, v und w als Binärzahlen aus
 *
 * @param keyoverflow   Gibt 1 zurück, falls es einen Überlauf gab, sonst ß
 * @param highlightPos  Die Bitposition, die rot ausgegeben werden soll
 */
ubyte test(ubyte u, ubyte v, int *keyoverflow, int highlightPos) {
    ubyte w = rotr(Feal_GS(u, v, keyoverflow));
    if (keyoverflow == 1) {
        printf("ERROR: keyoverflow = 1\n");
    }
    printf("\033[1mu\033[0m ");
    printBits(sizeof(u), &u, -1);
    printf("\033[1mv\033[0m ");
    printBits(sizeof(v), &v, -1);
    printf("\033[1mw\033[0m ");
    printBits(sizeof(w), &w, highlightPos);
    printf("\n");
    //printf(" overflow %d\n", *keyoverflow);
    return w;
}

/*
 * Prüft, ob Bit bitPos (0..7) von Byte u gesetzt ist
 */
int isBitSet(ubyte u, int bitPos)
{
    return (u & (1 << bitPos)) > 0;
}

/*
 * Findet im Array number den (ersten) Index (0..3), an dem das Bit bitPos (0..7)
 * gesetzt ist (bitValue = 1) oder nicht (bitValue = 0) und gibt diesen Index zurück
 */
int findBitWithValue(ubyte number[4], int bitPos, int bitValue) {
    int i;
    for (i = 0; i < 4; i++) {
        if (isBitSet(number[i], bitPos) == bitValue) {
            return i;
        }
    }
    return -1;
}

/*
 * Findet im Array number in Spalte/Bitposition bitPos (0..7) das Bit,
 * das anders als die drei anderen in dieser Spalte 0 oder 1 ist.
 *
 * @param bitValue  Wert des speziellen Bits
 * @return          Der Index in number, wo das spezielle Bit gefunden wurde
 */
int findSpecialBit(ubyte number[4], int bitPos, int *bitValue) {
    int index, i;
    int bitCount = 0;
    // sum last but one column
    for (i = 0; i < 4; i++) {
        bitCount += isBitSet(number[i], bitPos);
    }
    //printf("bitcount = %d\n", bitCount);
    if (bitCount == 3) {
        index = findBitWithValue(number, bitPos, 0);
    } else if (bitCount == 1) {
        index = findBitWithValue(number, bitPos, 1);
    } else {
        printf("\033[1;31mError: Invalid bit sum %d in column %d, expected 1 or 3\033[0m\n", bitCount, bitPos);
    }
    *bitValue = isBitSet(number[index], bitPos);
    return index;
}

void setBit(ubyte *number, int bitPosition)
{
    *number = *number | 1 << bitPosition;
}

void crack_k1_and_k2(ubyte *k1, ubyte *k2, ubyte *k3) {
    *k1 = 0;
    *k2 = 0;
    int keyoverflow, bitPos;
    ubyte w[4];

    for (bitPos = 1; bitPos <= 7; bitPos++) {
        // Berechne w für die vier Kombinationen von u und v
        w[0] = test(0, 0, &keyoverflow, bitPos);
        w[1] = test(1 << bitPos - 1, 0, &keyoverflow, bitPos);
        w[2] = test(0, 1 << bitPos - 1, &keyoverflow, bitPos);
        w[3] = test(1 << bitPos - 1, 1 << bitPos - 1, &keyoverflow, bitPos);

        // Finde das spezielle Bit für die aktuelle Bitposition, welches zeigt,
        // bei welchem Fall (u, v) der Überlauf war
        int specialBitValue;
        int specialBit = findSpecialBit(w, bitPos, &specialBitValue);
        printf("bit \033[31m%d\033[0m special at index %d, value %d\n", bitPos, specialBit, specialBitValue);

        // Setze Schlüsselbits für k1 und k2
        switch (specialBit)
        {
        case 0:
            setBit(k1, bitPos - 1);
            setBit(k2, bitPos - 1);
            break;
        case 1:
            setBit(k2, bitPos - 1);
            break;
        case 2:
            setBit(k1, bitPos - 1);
            break;
        case 3:
            break;
        default:
            printf("Error: expected specialBit index in range 0..3, got %d\n", specialBit);
        }
    }

    // Gebe gefundene Werte für k1 und k2 aus
    printf("k1 = ");
    printBits(sizeof(*k1), k1, -1);
    printf("\n");
    printf("k2 = ");
    printBits(sizeof(*k2), k2, -1);
    printf("\n");
}

int main(int argc, char **argv)
{
    ubyte k1,k2,k3;
    Feal_NewKey();
    crack_k1_and_k2(&k1, &k2, &k3);
    // TODO: k3 knacken
    k3 = 0;

    printf("Lösung: $%02x $%02x $%02x: %s",k1,k2,k3, Feal_CheckKey(k1,k2,k3)?"OK!":"falsch" );
    return 0;
}