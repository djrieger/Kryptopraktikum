/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 1: Klassische Chiffrierverfahren                  *
**                                                           *
**************************************************************
**
** vigenere_attacke.c: Brechen der Vigenere-Chiffre
**/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>
//#include <math.h>

#define NUMCHARS    26       /* Anzahl der Zeichenm, die betrachtet werden ('A' .. 'Z') */
#define MaxFileLen  32768    /* Maximale Größe des zu entschlüsselnden Textes */

const char *StatisticFileName = "statistik.data";  /* Filename der Wahrscheinlichkeitstabelle */
const char *WorkFile          = "testtext.ciph";   /* Filename des verschlüsselten Textes */

double PropTable[NUMCHARS]; /* Tabellke mit den Zeichenwahrscheinlichkeiten.
                 * ProbTable[0] == 'A', PropTable[1] == 'B' usw. */
char TextArray[MaxFileLen]; /* die eingelesene Datei */
int TextLength;             /* Anzahl der gültigen Zeichen in TextArray */

/*--------------------------------------------------------------------------*/

/*
 * GetStatisticTable(): Liest die Statistik-Tabelle aus dem File
 * STATISTICFILENAME in das globale Array PROPTABLE ein.
 */

static void GetStatisticTable(void)
{
    FILE *inp;
    int i;
    char line[64];

    if (!(inp = fopen(StatisticFileName, "r")))
    {
        fprintf(stderr, "FEHLER: File %s kann nicht geöffnet werden: %s\n",
                StatisticFileName, strerror(errno));
        exit(20);
    }

    for (i = 0; i < TABSIZE(PropTable); i++)
    {
        fgets(line, sizeof(line), inp);
        if (feof(inp))
        {
            fprintf(stderr, "FEHLER: Unerwartetes Dateieine in %s nach %d Einträgen.\n",
                    StatisticFileName, i);
            exit(20);
        }
        PropTable[i] = atof(line);
    }
    fclose(inp);
}

/*-------------------------------------------------------------------------*/

/* GetFile(void) : Ließt den verschlüsselten Text aus dem File
 *   WORKFILE zeichenweise in das globale Array TEXTARRAY ein und zählt
 *   TEXTLENGTH für jedes Zeichen um 1 hoch.
 *   Eingelesen werden nur Buchstaben. Satz- und Sonderzeichen werden weggeworfen,
 *   Kleinbuchstaben werden beim Einlesen in Großbuchstaben gewandelt.
 */

static void GetFile(void)
{
    FILE *inp;
    char c;

    if (!(inp = fopen(WorkFile, "r")))
    {
        fprintf(stderr, "FEHLER: File %s kann nicht geöffnet werden: %s\n",
                WorkFile, strerror(errno));
        exit(20);
    }

    TextLength = 0;
    while (!feof(inp))
    {
        c = fgetc(inp);
        if (feof(inp)) break;
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c >= 'A' && c <= 'Z')
        {
            if (TextLength >= sizeof(TextArray))
            {
                fprintf(stderr, "FEHLER: Eingabepuffer nach %d Zeichen übergelaufen!\n", TextLength);
                exit(20);
            }
            TextArray[TextLength++] = c;
        }
    }
    fclose(inp);
}


/*--------------------------------------------------------------------------*/

/*
 * CountChars( int start, int offset, int h[] )
 *
 * CountChars zählt die Zeichen (nur Buchstaben!) im globalen Feld
 * TEXTARRAY. START gibt an, bei welchen Zeichen (Offset vom Begin der
 * Tabelle) die Zählung beginnen soll und OFFSET ist die Anzahl der
 * Zeichen, die nach dem 'Zählen' eines Zeichens weitergeschaltet
 * werden soll. 'A' wird in h[0], 'B' in h[1] usw. gezählt.
 *
 *  Beispiel:  OFFSET==3, START==1 --> 1,  4,  7,  10, ....
 *             OFFSET==5, START==3 --> 3,  8, 13,  18, ....
 *
 * Man beachte, daß das erste Zeichen eines C-Strings den Offset 0 besitzt!
 */

static void CountChars( int start, int offset, int h[NUMCHARS])
{
    int i;
    // 1.

    //printf("CountChars: start = %d, offset = %d\n", start, offset);

    for (i = 0; i < NUMCHARS; i++) h[i] = 0;
    for (i = start - 1; i < TextLength; i = i + offset)
        h[TextArray[i] - 'A']++;
}

static void CountRelativeChars(int start, int offset, double rel_h[NUMCHARS])
{
    int h[NUMCHARS];
    CountChars(start, offset, h);
    int i;
    for (i = 0; i < NUMCHARS; i++)
        rel_h[i] = (double)h[i] / TextLength;
}

int findMaxPos(double rel_h[NUMCHARS], double *maximum)
{
    int i;
    int index = -1;
    *maximum = 0;
    for (i = 0; i < NUMCHARS; i++)
        if (rel_h[i] > *maximum)
        {
            *maximum = rel_h[i];
            index = i;
        }

    return index;
}

double absFoo(double foo)
{
	return foo < 0 ? -foo : foo;
}

static void crack()
{
	int i;
	/**
    double foo = 0;
    
    for (i = 0; i < NUMCHARS; i++)
    {
        foo +=  PropTable[i] * PropTable[i];
    }
    printf("Summe p_i^2 = %.4f", foo); // = 0.662
	*/


    double h[NUMCHARS];
    CountRelativeChars(1, 1, h);

    // 2. (4.2)
    double Ic = 0;
    for (i = 0; i < NUMCHARS; i++)
    {
        Ic += h[i] * h[i];
    }

    printf("Ic = %.4f\n", Ic);
    printf("TextLength = %d\n", TextLength);

    // 2. (4.4)
    int n = TextLength;
    //int l_ = (269 * n) / ((169 - 2600 * Ic) + (100 + 2600 * Ic) * n);
    //(269 * 18970) / ((169 - 2600 * 0.0401) + (100 + 2600 * 0.0401) * 18970)
    //printf("according to formula (4.4) l = %d\n", l_);

    // find character with maximum probability in PropTable
    double propTableMax = -1;
    int propTableMaxPos = findMaxPos(PropTable, &propTableMax);
    printf("propTable has maxmimum %.4f at %d\n", propTableMax, propTableMaxPos);

    int l;
    int minDiffL = -1;
    double diff = 10000;
    //for (l = l_ - 2; l <= l_ + 2; l++)
 	for (l = 1; l < 20; l++)
    {
    	double Ic_l = (float)(n - l)/(l*(n-1)) * 0.065 + (float)((l-1)*n)/(l*(n-1)) / 26.0;
    	if (absFoo(Ic_l - Ic) < diff) {
    		diff = absFoo(Ic_l - Ic);
    		minDiffL = l;
    	}
    	printf("Ic-Kandidat für l = %d: %.4f, diff = %.6f\n", l, Ic_l, absFoo(Ic_l - Ic));
	}
	printf("minDiffL = %d\n\n\n", minDiffL);


    for (l = minDiffL - 2; l <= minDiffL + 2; l++)
    //for (l = minDiffL; l <= minDiffL; l++)
    {
    	printf("l = %d: ", l);
        int start;

        char key[l + 1];

        for (start = 1; start <= l; start++)
        {
            // 3.
            // count relative occurrences of Caesar start, start + l, ...
            // and determine character with highest probability (at hMaxPos)
            CountRelativeChars(start, l, h);
            double hMax = -1;
            int hMaxPos = findMaxPos(h, &hMax);


            //printf("l = %d, hMax = %.4f, propMax = %.4f\n", l, hMax, propTableMax);
            //if ()
            //{
                //printf("Key length should be l = %d\n", l);
                int shift = (hMaxPos - propTableMaxPos);
                char shiftChar;
                if (shift > 0)
                	 shiftChar = shift + 'A' - 1; //shift < 0 ? 'Z' + shift + 1 : 'A' + shift - 1;
                else
                	shiftChar = shift + 'Z';
                key[start - 1] = shiftChar;
                //printf("hMaxPos = %d, Shift = %d (%c)\n", hMaxPos, shift, shiftChar);
                
            //}
        }
        key[l] = '\0';
        printf("%s\n", key);
        //printf("-----------\n");
    }
}


/*------------------------------------------------------------------------------*/

int main(int argc, char **argv)
{

    GetStatisticTable();     /* Wahrscheinlichkeiten einlesen */
    GetFile();               /* zu bearbeitendes File einlesen */

    /*****************  Aufgabe  *****************/
    crack();
    return 0;
}
