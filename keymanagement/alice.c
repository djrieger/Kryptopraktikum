/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 5: Keymanagement mit dem Kerberos-Protokoll       *
**                                                           *
**************************************************************
**
** alice.c: Hauptprogram für den Kommunikationspartner ALICE
**/

#include "kerberos.h"

/* Unser 'Netzwerk'-Name und die unserer Kommunikationspartner */
const char *OurName    = "Alice";
const char *OthersName = "Bob";
const char *ServerName = "Server";

/* Der geheime, gemeinsame Schlüssel zwischen dem Server und Alice */
DES_key Key_AS = { 0x12, 0x7f, 0x5f, 0xac, 0x09, 0xf3, 0xd2, 0xa0 };

/* Der vom Server generierte Schlüssel für die Kommunikation mit Bob 
 * in der internen Darstellung (generiert mit DES_GenKeys() */
DES_ikey iKey_AB;

/* Zur Ver- und Entschlüsselung der ausgetauschten Daten wird der
 * DES im Output Feedback Mode eingesetzt, weil hier ohne großen
 * Aufwand auch Datenblöcke, deren Länge nicht durch 8 teilbar sind,
 * bearbeitet werden können. Die Initialisierungsvektoren IV für die
 * heweilige Verschlüsselung werden in IV1 und IV2 gespeichert. */
DES_data phone_iv1,phone_iv2;

/* ------------------------------------------------------------------------------ */

/*
 * EnCrypt(c) : Verschlüsselt C mit KEY_AB/PHONE_IV1
 */

static char EnCrypt(char c)
  {
    /*>>>>         <<<<*
     *>>>> AUFGABE <<<<*
     *>>>>         <<<<*/
  }


/*
 * DeCrypt(c) : Entschlüsselt C mit KEY_AB/PHONE_IV2
 */

static char DeCrypt(char c)
  {
    /*>>>>         <<<<*
     *>>>> AUFGABE <<<<*
     *>>>>         <<<<*/
  }

/* ------------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
  Connection con;
  Message msg1,msg2;
  char *OurNetName, *OthersNetName, *ServerNetName;

  /* Konstruktion eindeutiger Namen für das Netzwerksystem:
   * OurName, OthersName und ServerName wird der Gruppenname vorangestellt.
   * So gibt es KEINE Kollisionen zwischen den einzelnen Gruppen!
   * Dieser Netzname wird nur für den Verbindungsaufbau über das
   * E.I.S.S.-Network-Playfield benutzt. Die im Rahmen des Protokolls
   * ausgetauschten Namen sind OutName, OthersName und ServerName!
   */

  OurNetName    = MakeNetName(OurName);
  OthersNetName = MakeNetName(OthersName);
  ServerNetName = MakeNetName(ServerName);

  /***************  Verbindungsaufbau zum Server  ********************/
  /* Die Verbindung zum Server muß einen anderen "Quell"-Namen haben, als
   * die zu Bob. Daher hängen wir einfach ein _S an! */
  if (!(con=ConnectTo(concatstrings(OurNetName,"_S",NULL),ServerNetName))) {
    fprintf(stderr,"ALICE: Kann keine Verbindung zum Server aufbauen: %s\n",NET_ErrorText());
    exit(20);
  }

  /******  Paket mit den beiden Namen erzeugen und Abschicken  *******/

  // 1 Alice -> Server
  
  msg1.typ = Alice_Server;
  strcpy(msg1.body.Alice_Server.A,OurName);
  strcpy(msg1.body.Alice_Server.B,OthersName);
  PutMessage("Server",con,&msg1);
  /***********  Antwort des Servers lesen  ***********/

  // 2 Server -> Alice
  GetMessage("Server",con,&msg2,Server_Alice);
  printf("%d\n", msg2.body.Server_Alice.Serv_A1.TimeStamp);

  /****************  Verbindung zum Server abbauen  *************/
  /*>>>>                                         <<<<*
   *>>>> AUFGABE: - Entschlüsseln der Nachricht  <<<<*
   *>>>>          - Nachrichtenaustauch mit Bob  <<<<*
   *>>>>          - Überprüfen der Bob-Nachricht <<<<*
   *>>>>          - Schlüssel für Telefonieren   <<<<*
   *>>>>                                         <<<<*/
  DisConnect(con);

  // 3 Alice -> Bob 
  printf("Bob: Trying to connect to %s...\n", OthersNetName);
  if (!(con=ConnectTo(concatstrings(OurNetName,"_S",NULL),OthersNetName))) {
    fprintf(stderr,"ALICE: Kann keine Verbindung zu Bob aufbauen: %s\n",NET_ErrorText());
    exit(20);
  }
  
  ServerData bobsPackage;
  bobsPackage = msg2.body.Server_Alice.Serv_B1;

  Message msg3;
  msg3.typ = Alice_Bob;
  msg3.body.Alice_Bob.Serv_B2 = bobsPackage;

  AuthData authData;
  authData.Rand = 42;
  strcpy(authData.Name, MakeNetName("Alice"));
  msg3.body.Alice_Bob.Auth_A2 = authData;
  PutMessage("Bob",con,&msg3);

  printf("Alice: Sent message to Bob\n");


  // 4 Bob -> Alice
  Message msg4;
  printf("Alice: Getting message from Bob...\n");
  GetMessage("Bob", con, &msg4, Bob_Alice);
  printf("Alice: Got message from Bob\n");
  printf("%d\n", msg4.body.Bob_Alice.Auth_B3.Rand);



  printf("disconnecting\n");
  DisConnect(con);
  
  /***********************  Phone starten  *****************************/
  Phone(con,OurName,OthersName,EnCrypt,DeCrypt);
  return 0;
}
