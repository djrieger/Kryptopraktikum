/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 5: Keymanagement mit dem Kerberos-Protokoll       *
**                                                           *
**************************************************************
**
** bob.c: Hauptprogram für den Kommunikationspartner BOB
**/

#include "kerberos.h"

/* Unser 'Netzwerk'-Name und die unserer Kommunikationspartner */
const char *OurName    = "Bob";
const char *OthersName = "Alice";

/* Der geheime, gemeinsame Schlüssel zwischen dem Server und Bob */
DES_key Key_BS = { 0x7f, 0xab, 0x12, 0xa0, 0x4d, 0xc6, 0x81, 0x02 };

/* Der vom Server generierte Schlüssel für die Kommunikation mit Alice
 * in der internen Darstellung (generiert mit DES_GenKeys() */
DES_ikey iKey_AB;

/* Zur Ver- und Entschlüsselung der ausgetauschten Daten wird der
 * DES im Output Feedback Mode eingesetzt, weil hier ohne großen
 * Aufwand auch Datenblöcke, deren Länge nicht durch 8 teilbar sind,
 * bearbeitet werden können. Die Initialisierungsvektoren IV für die
 * heweilige Verschlüsselung werden in IV1 und IV2 gespeichert. */
DES_data phone_iv1 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
DES_data phone_iv2 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

/* ------------------------------------------------------------------------------ */



static char EnCrypt(char c)
  {
    DES_CFB_Enc(iKey_AB, phone_iv1, &c, sizeof(c), &c);
    return c;
  }


/*
 * DeCrypt(c) : Entschlüsselt C mit KEY_AB/PHONE_IV2
 */

static char DeCrypt(char c)
  {
   DES_CFB_Dec(iKey_AB, phone_iv2, &c, sizeof(c), &c);
    return c;
  }
/* -------------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
  Connection con;
  Message msg1,msg2;
  char *OurNetName,*OthersNetName;

  /* Konstruktion eindeutiger Namen für das Netzwerksystem:
   * OurName, OthersName und ServerName wird der Gruppenname vorangestellt.
   * So gibt es KEINE Kollisionen zwischen den einzelnen Gruppen!
   * Dieser Netzname wird nur für den Verbindungsaufbau über das
   * E.I.S.S.-Network-Playfield benutzt. Die im Rahmen des Protokolls
   * ausgetauschten Namen sind OutName, OthersName und ServerName!
   */

  OurNetName    = MakeNetName(OurName);
  OthersNetName = MakeNetName(OthersName);

  printf("Bob: Trying to connect to %s...\n", OthersNetName);
  /***************  Verbindungsaufbau zu Alice  ********************/

  printf("\nWarten auf eine Verbindung von Alice ....\n");
  PortConnection port;
  if (!(port=OpenPort(OurNetName))) {
    fprintf(stderr,"Kann das Serverport nicht erzeugen: %s\n",NET_ErrorText());
    exit(20);
  }
    if (!(con=WaitAtPort(port))) {
      fprintf(stderr,"WaitAtPort ging schief: %s\n",NET_ErrorText());
      exit(20);
    }

  /***********  Paket von Alice mit Server- und Auth-Daten lesen **********/

  printf("Bob: Connected to Alice\n");
  printf("Bob: Trying to get message from Alice\n");

  GetMessage(OthersName,con,&msg1,Alice_Bob);
  printf("Bob: Received message from Alice\n");


  DES_key k_AB;
  strncpy(k_AB, msg1.body.Alice_Bob.Serv_B2.Key_AB, sizeof(DES_key));
  DES_GenKeys(k_AB, 1, iKey_AB);

    /*>>>>                                       <<<<*
     *>>>> AUFGABE: - Paket von Alice auspaken   <<<<*
     *>>>>          - Antwort erzeugen           <<<<*
     *>>>>          - Schlüssel für telefonieren <<<<*
     *>>>>                                       <<<<*/

  // 4 Bob -> Alice   
  msg1.typ = Bob_Alice;
  printf("%d\n", msg1.body.Alice_Bob.Auth_A2.Rand);
  AuthData authData;
  authData.Rand = msg1.body.Alice_Bob.Auth_A2.Rand + 1;
  strcpy(authData.Name, MakeNetName("Bob"));
  PutMessage("Alice",con,&msg1);

  /***********************  Phone starten  *****************************/
  Phone(con,OurName,OthersName,EnCrypt,DeCrypt);
  DisConnect(con);
  return 0;
}

