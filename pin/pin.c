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
#include <math.h>

#include "pin.h"

int diff1, diff2;


int pin[9000], prob[9000], trypin[9000];


void attack(void)
{
    int i, j, pin1, pin2, pin3, pin4;
    int pins[65536][4];

    // prob = 0

    for (i = 1000; i <= 9999; i++)
    {
    	pin[i - 1000] = i;
    	prob[i - 1000] = 0;
    }

    i = 0;
    for (pin1 = 0; pin1 < 16; pin1++)
    	for (pin2 = 0; pin2 < 16; pin2++)
    		for (pin3 = 0; pin3 < 16; pin3++)
    			for (pin4 = 0; pin4 < 16; pin4++)
    			{
    				pins[i][0] = map(pin1);
    				//if (pins[i][0] == 0)
    				//	pins[i][0] = 1;
    				pins[i][1] = map(pin2);
    				pins[i][2] = map(pin3);
    				pins[i][3] = map(pin4);

    				printf("%d%d%d%d\n", pins[i][0], pins[i][1], pins[i][2], pins[i][3]);


    				//printf("%d%d%d%d == ", pins[i][0], pins[i][1], pins[i][2], pins[i][3]);
    				int pinCandidate = pins[i][3] + 10 * pins[i][2] + 100 * pins[i][1] + 1000 * pins[i][0];

    				char diffString[5];
    				//itoa(diff1, diffString, 10);
    				sprintf(diffString,"%d",diff1);
    				int index = 0;
    				for (j = 3; j >= 0; j--)
    					index += (((diffString[j] - '0') - pins[i][j]) % 10) * pow(10, 3 - j);
    				printf("%d/%s - %d = %d\n", diff1, diffString, pinCandidate, index);
    				//printf("%d", index);
    				prob[index - 1000]++;
    				//printf(" (prob = %d)\n", prob[index]);

    				i++;
    				if (i >= 50)
    					return 0;
    			}

//    printf("---------\n");
    //for (i = 0; i < 50; i++)
	//	printf("%d: %d\n", pin[i], prob[i]);    			

	// sort
	int highestProb = -1;
	int highestProbIndex = -1;
	
	for (i = 0; i < 100; i++)
    {
    	for (j = 0; j < 9000; j++)
    	{
    		if (prob[j] > highestProb) {
    			highestProb = prob[j];
    			highestProbIndex = j;
    		}
    	}

    	trypin[i] = pin[highestProbIndex];    	
    	printf("%d correct = %d\n", trypin[i], try_pin(trypin[i]));
    	//printf("%d: %d\n", trypin[i], highestProb);

    	highestProb = -1;
    	prob[highestProbIndex] = -1;
    }
    //printf("%d\n", try_pins(trypin, 100));
}

int map(int c)
{
	return c <= 9 ? c : c - 10;
}

int main(void)
{
	open_connection(0, &diff1, &diff2);
	printf("diff1 %d, diff2 %d\n", diff1, diff2);
	
	attack();
	close_connection();
	exit(0);
}
