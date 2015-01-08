/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 5: Keymanagement mit dem Kerberos-Protokoll       *
**                                                           *
**************************************************************
**
** server.c: Hauptprogram für den Security-Server
**/

#include "kerberos.h"

/* Unser 'Netzwerk'-Name und die unserer Kommunikationspartner */
const char *ServerName = "Server"; 
/* #define BADSERVER */ /* wenn definiert, wird der Verkehr zwischen den beiden Partnern abgehört. */

const char *AliceName = "Alice"; 

struct UserEntry {
  const char *Name;   /* name des Benutzers */
  DES_key Key;        /* Geheimer Schlüssel */
};

/* tabelle der Benutzer mit ihren geheimen Schlüsseln */
const struct UserEntry UserTable[] = {
  { "Alice", { 0x12, 0x7f, 0x5f, 0xac, 0x09, 0xf3, 0xd2, 0xa0 } },
  { "Bob",   { 0x7f, 0xab, 0x12, 0xa0, 0x4d, 0xc6, 0x81, 0x02 } },
  { "Carol", { 0x6f, 0x18, 0xa5, 0xcf, 0x11, 0x4e, 0xab, 0xf0 } }
};


DES_data phone_iv1,phone_iv2;
DES_ikey ikey_ab;

/* ------------------------------------------------------------------------------ */

static char DeCrypt1(char c)
  {
    /*>>>>         <<<<*
     *>>>> AUFGABE <<<<*
     *>>>>         <<<<*/


  }

static char DeCrypt2(char c)
  {
    /*>>>>         <<<<*
     *>>>> AUFGABE <<<<*
     *>>>>         <<<<*/
  }

/* ------------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
  Connection con;        /* Verbindung vom Clienten d.h. Alice */
  PortConnection port;   /* Das Port des Servers */
  Message msg1,msg2,msg3;
  int i,a_pos,b_pos,badserver;
  char *ServerNetName;

  /* Konstruktion eindeutiger Namen für das Netzwerksystem:
   * OurName, OthersName und ServerName wird der Gruppenname vorangestellt.
   * So gibt es KEINE Kollisionen zwischen den einzelnen Gruppen!
   * Dieser Netzname wird nur für den Verbindungsaufbau über das
   * E.I.S.S.-Network-Playfield benutzt. Die im Rahmen des Protokolls
   * ausgetauschten Namen sind OutName, OthersName und ServerName!
   */

  ServerNetName = MakeNetName(ServerName);
  badserver = (argc>1); /* Bei Argument: Bösen Server spielen! */
  if (badserver) printf("**** Warnung, dieser Server ist kompromitiert ****\n");

  /***************  Globales Port eröffnen  ***************/
  if (!(port=OpenPort(ServerNetName))) {
    fprintf(stderr,"Kann das Serverport nicht erzeugen: %s\n",NET_ErrorText());
    exit(20);
  }

  while (1) { /* Für immer ... */

    /**************  Auf Verbindung auf dem Port warten  ****************/
    printf("\nWarten auf eine Verbindung ....\n");
    if (!(con=WaitAtPort(port))) {
      fprintf(stderr,"WaitAtPort ging schief: %s\n",NET_ErrorText());
      exit(20);
    }

    /*****************  Request von 'Alice' einlesen  *******************/
    GetMessage("Clinet",con,&msg1,Alice_Server);
    printf("SERVER: Key-Request von %s für Verbindung mit %s\n",
	   msg1.body.Alice_Server.A,msg1.body.Alice_Server.B);

    /* Suchen der beiden Partner in der Benutzertabelle */
    a_pos = b_pos = -1;
    for (i=0; i<TABSIZE(UserTable); i++) {
      if (!strcmp(UserTable[i].Name,msg1.body.Alice_Server.A)) a_pos=i;
      else if (!strcmp(UserTable[i].Name,msg1.body.Alice_Server.B)) b_pos=i;
    }

    if (a_pos==-1) {
      printf("Fehler: Benutzer %s nicht gefunden.\n",msg1.body.Alice_Server.A);
      msg2.typ = Error;
      strcpy(msg2.body.Error.ErrorText,"Unbekannter Benutzer ");
      strcat(msg2.body.Error.ErrorText,msg1.body.Alice_Server.A);
      PutMessage("Client",con,&msg2);
    }
    else if (b_pos==-1) {
      printf("Fehler: Benutzer %s nicht gefunden.\n",msg1.body.Alice_Server.B);
      msg2.typ = Error;
      strcpy(msg2.body.Error.ErrorText,"Unbekannter Benutzer ");
      strcat(msg2.body.Error.ErrorText,msg1.body.Alice_Server.B);
      PutMessage("Client",con,&msg2);
    }
    else {
      /*>>>>                                                 <<<<*
       *>>>> AUFGABE: - Schlüssel für Alice und Bob erzeugen <<<<*
       *>>>>          - Antwortpaket an Alice senden         <<<<*
       *>>>>          - Kommunikation abhören                <<<<*
       *>>>>                                                 <<<<*/
       //Generates random UBYTE[] - used for IV and k_ab
       /**DES_key result[8];
       int i;
       srand(time(NULL));
       for(i=0; i< sizeof(result); i++){
          result[i] = rand() % 256;
         printf("result[%d] = %d\n", i, result[i]);
        }
        */

        //k_AB = result;


       // Gathering ServerData
       DES_key k_AB = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

       int timestamp = (unsigned)time(NULL);


      // int i;
       //for(i = 0; i < 3; i++)
       //printf("%x", UserTable[0].Key[i]);

       //data mit K_BS verschlüsseln
       DES_ikey b_ikey;
       DES_GenKeys(UserTable[b_pos].Key,0,&b_ikey);


       //fprint("b_ikey: %d\n", b_ikey);

       /* DES_OFB ver- bzw. entschlüsselt LEN Bytes von SRC nach DST im
        * Output Feedback Mode (Rückkopplungsbreite: * Bytes). LEN muß NICHT
        * durch 8 teilbar sein! */
       //UBYTE dest_b;
       //DES_OFB(*b_ikey, result, &data, sizeof(data), &dest_b);
       

       ServerData data = {timestamp, {k_AB[0],k_AB[1],k_AB[2],k_AB[3],k_AB[4],k_AB[5],k_AB[6],k_AB[7]}, "Alice"};
      

       //{{data}K_BS und timestamp, K_AB, B} mit K_AS verschlüsseln

       msg3.typ =  Server_Alice;
       msg3.body.Server_Alice.Serv_A1 = data;

      printf("%s\n", msg3.body.Server_Alice.Serv_A1.Receiver);

       PutMessage("Alice",con,&msg3);
    }

    /* Verbindung zu Alice abbauen */
    DisConnect(con);
  }

  return 0;
  }