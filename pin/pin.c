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
int pin[9000], prob[9000], try[9000], joinedProbs[9000];
float prob2[9000], try2[9000];
int pins[65536][4];
int finalPins[100];


int attack(void)
{
    //calc result with diffs --->seperate methode
	int k = 0;
	int i, j, index;
	for(k; k < 9000;k++){
		int pinCandidate = pins[k][3] + 10 * pins[k][2] + 100 * pins[k][1] + 1000 * pins[k][0];//only for debugging
		char diffString1[5], diffString2[5];
		//itoa(diff1, diffString, 10);
		sprintf(diffString1,"%d",diff1);
		if(diffString1[3] - '0' < 0 )
		{
			diffString1[3] = diffString1[2];
			diffString1[2] = diffString1[1];
			diffString1[1] = diffString1[0];
			diffString1[0] = 48;
		}
		if(diffString1[3] - '0' < 0 )
		{
			diffString1[3] = diffString1[2];
			diffString1[2] = diffString1[1];
			diffString1[1] = diffString1[0];
			diffString1[0] = 48;
		}
		
		if(diffString2[3] - '0' < 0 )
		{
			diffString2[3] = diffString2[2];
			diffString2[2] = diffString2[1];
			diffString2[1] = diffString2[0];
			diffString2[0] = 48;
		}
		if(diffString2[3] - '0' < 0 )
		{
			diffString2[3] = diffString2[2];
			diffString2[2] = diffString2[1];
			diffString2[1] = diffString2[0];
			diffString2[0] = 48;
		}
		index = 0;
		
		for (j = 3; j >= 0; j--){
			if((((diffString1[0] - '0') + pins[k][0]) % 10) != 0)
				index += (((diffString1[j] - '0') + pins[k][j]) % 10) * pow(10, 3 - j);
		}
		//printf("%d", index);
		try[index - 1000]++;
		//printf(" (prob = %d)\n", prob[index]);
		index = 0;
		for (j = 3; j >= 0; j--){
			if((((diffString2[0] - '0') + pins[k][0]) % 10) != 0)
				index += (((diffString2[j] - '0') + pins[k][j]) % 10) * pow(10, 3 - j);
		}
		//printf("%d", index);
		try[index - 1000]++;
		
		/*if (k < 20)//Debugging
			{
				printf("%d/%s + %d = %d\n", diff1, diffString1, pinCandidate, index);
				printf("Index: %d / Pin am Index: %d%d%d%d\n", index, pins[index][0], pins[index][1], pins[index][2], pins[index][3]);
				//printf("%d%d%d%d\n", pins[i][0], pins[i][1], pins[i][2], pins[i][3]);
		}*/
		
		
		
	}
	for(i=0;i<9000;i++){
		try2[i] = (float) try[i]/9000;
	}
	
	for(i=0;i<9000;i++)
		joinedProbs[i] = try2[i] * prob2[i];
		
	//Sort probs-Array by highest amount of occurences of pins
	int highestProb = -1;
	int highestProbIndex = -1;
	
	for (i = 0; i < 100; i++)
    {
    	for (j = 0; j < 9000; j++)
    	{
    		if (joinedProbs[j] > highestProb) {
    			highestProb = joinedProbs[j];
    			highestProbIndex = j;
    		}
    	}
		
    	finalPins[i] = pin[highestProbIndex];    	
    	//printf("%d correct = %d\n", trypin[i], try_pin(trypin[i]));
    	//printf("%d: %d\n", trypin[i], highestProb);

    	highestProb = -1;
    	joinedProbs[highestProbIndex] = -1;
    }				
	int correct = try_pins(finalPins, 100);
	printf("%d\n", correct);
	return correct;

}

void init(void){
int i, pin1, pin2, pin3, pin4;
    
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
    				if (pins[i][0] == 0)
    					pins[i][0] = 1;
    				pins[i][1] = map(pin2);
    				pins[i][2] = map(pin3);
    				pins[i][3] = map(pin4);

    				//printf("%d%d%d%d == ", pins[i][0], pins[i][1], pins[i][2], pins[i][3]);
    				int index = pins[i][3] + 10 * pins[i][2] + 100 * pins[i][1] + 1000 * pins[i][0] - 1000;
    				//printf("%d", index);
    				prob[index]++;
    				//printf(" (prob = %d)\n", prob[index]);

    				i++;
    				//if (i >= 50)
    				//	return 0;
    			}

    printf("---------\n");
	
	//calculate probabilities
	for(i=0;i<9000;i++)
		prob2[i] = (float) prob[i]/9000;
	//debugging
    //for (i = 0; i < 50; i++)
		//printf("%d: %d ===> %.9f\n", pin[i], prob[i], prob2[i]);  
	return;
}

int map(int c)
{
	return c <= 9 ? c : c - 10;
}

int main(void)
{
	char diffString1[5];
	int l = 0, correct = 0, i, start = 0;
	init();
	for(l;l<=100;l++){
		init();
		open_connection(0, &diff1, &diff2);
		
		printf("Versuch: %d: ", l);
		if(attack() != -1){
			correct++;
			if(start == 0){
				//start = 1;
				//l = 0;
				}
		}
		close_connection();
		if(l==100){
			printf("\n Correct: %d/100\n\n", correct);
			if(correct < 10){
				l=0;
				correct= 0;
				//start = 0;
			}
		}
		}
	exit(0);
}
