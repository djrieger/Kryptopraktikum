/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 3: Brechen von EC-Karten PINs                     *
**                                                           *
**************************************************************
**
** pin.c Headerfile für den PIN-Versuch
**/

#include <stdio.h>
#include <stdlib.h>

#include "pin.h"

int diff1, diff2;


int pin[9000], prob[9000], try[9000];


void attack(void)
{
    int i;
    /*>>>>                                                      <<<<*/
    /*>>>>  Aufgabe: Bestimmen die PIN                          <<<<*/
    /*>>>>                                                      <<<<*/
    printf("Die PIN ist: %d\n", i);

}

int map(int c)
{
	return c <= 9 ? c : c - 10;
}

int main(void)
{
    int i, pin1, pin2, pin3, pin4;
    int pins[65536][4];

    i = 0;
    for (pin1 = 0; pin1 < 16; pin1++)
    	for (pin2 = 0; pin2 < 16; pin2++)
    		for (pin3 = 0; pin3 < 16; pin3++)
    			for (pin4 = 0; pin4 < 16; pin4++)
    			{
    				pins[i][0] = map(pin1);
    				if (pins[i][0] == 0)
    					pins[i][0] = 1;
    				pins[i][1] = map(pin2);
    				pins[i][2] = map(pin3);
    				pins[i][3] = map(pin4);

    				printf("%d%d%d%d\n", pins[i][0], pins[i][1], pins[i][2], pins[i][3]);

    				i++;
    				if (i >= 50)
    					return 0;
    			}
	return 0;

	open_connection(0, &diff1, &diff2);
	attack();
	close_connection();
	exit(0);
}
