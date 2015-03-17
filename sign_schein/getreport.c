/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 7: El-gamal-Signatur                              *
**                                                           *
**************************************************************
**
** getreport.c: Rahmenprogramm für den Signatur-Versuch
**/


/* 
 * OverrideNetName: Hier den Gruppennamen einsetzen, falls der nicht 
 *                  mit dem Accountnamen uebereinstimmt
 *                  Andernfalls leerer String
 */

static const char *OverrideNetName = "rilokru";



#include "sign.h"

static longnum p,w;

/*
 * Verify_Sign(mdc,r,s,y) :
 *
 *  überprüft die El-Gamal-Signatur R/S zur MDC. Y ist der öffentliche
 *  Schlüssel des Absenders der Nachricht
 *
 * RETURN-Code: 1, wenn Signatur OK, 0 sonst.
 */
static int Verify_Sign(const_longnum_ptr mdc, const_longnum_ptr r, const_longnum_ptr s, const_longnum_ptr y)
  {
    /*>>>>                                               <<<<*
     *>>>> AUFGABE: Verifizieren einer El-Gamal-Signatur <<<<*
     *>>>>                                               <<<<*/
    longnum tmp_left, tmp_right;
    LInitNumber(&tmp_left, NBITS(&p), 0);
    LInitNumber(&tmp_right, NBITS(&p), 0);
 
    LModMultExp(y, r, r, s, &tmp_left, &p); // (y^r * r^s) mod p
 
    LModExp(&w, mdc, &tmp_right, &p); // w^m mod p
 
    //printf("Vergleich ergibt: %i\n", (LCompare(&tmp_left, &tmp_right) == 0));
   return (LCompare(&tmp_left, &tmp_right) == 0);
  }
 
 
/*
* Generate_Sign(m,r,s,x) : Erzeugt zu der MDC M eine El-Gamal-Signatur
 *    in R und S. X ist der private Schlüssel
*/
static void Generate_Sign(const_longnum_ptr m, longnum_ptr r, longnum_ptr s, const_longnum_ptr x)
  {
    /*>>>>                                           <<<<*
     *>>>> AUFGABE: Erzeugen einer El-Gamal-Signatur <<<<*
     *>>>>                                           <<<<*/
    longnum k;
    LInitNumber(&k, NBITS(&p), 0);
 
    longnum mod;
    LCpy(&mod, &p);
                // mod ist nun p
   
                longnum EINS;
    LInitNumber(&EINS, NBITS(&p), 0);
    LInt2Long(1, &EINS);
 
    LSub(&EINS, &mod);
    // mod ist nun p-1
 
    // Suche gültige Zufallszahl
    do {
      LRand(&p, &k);
    } while(LInvert(&k, &mod)); // k < p - 1 AND ggT(k, p-1) = 1 <=> k invertierbar
 
    LModExp(&w, &k, r, &p);
    // r ist nun w^k mod p
    
    longnum tmp;
    LInitNumber(&tmp, NBITS(&p), 0);
    LModMult(r, x, &tmp, &mod);
    LCpy(s, m);
    LSubMod(&tmp, s, &mod);
    // s beinhaltet nun (m - r*x) mod (p-1)
 
    LCpy(&tmp, &k);
    LInvert(&tmp, &mod);
    // tmp beinhaltet nun k^-1
 
    LModMult(s, &tmp, s, &mod);
    // s = (m - r*x) * k^-1 mod (p-1)
  }


int main(int argc, char **argv)
{
  Connection con;
  int cnt,ok;
  Message msg;
  longnum x,Daemon_y,mdc;
  const char *OurName;

  /**************  Laden der öffentlichen und privaten Daten  ***************/
  if (!Get_Privat_Key(NULL,&p,&w,&x) || !Get_Public_Key(DAEMON_NAME,&Daemon_y)) exit(0);
  LSeed(GetCurrentTime());


  /********************  Verbindung zum Dämon aufbauen  *********************/
  OurName = MakeNetName(NULL); /* gibt in Wirklichkeit Unix-Gruppenname zurück! */
  if (strlen(OverrideNetName)>0) {
    OurName = OverrideNetName;
  }
  if (!(con=ConnectTo(OurName,DAEMON_NAME))) {
    fprintf(stderr,"Kann keine Verbindung zum Daemon aufbauen: %s\n",NET_ErrorText());
    exit(20);
  }


  /***********  Message vom Typ ReportRequest initialisieren  ***************/
  msg.typ  = ReportRequest;                       /* Typ setzten */
  strcpy(msg.body.ReportRequest.Name,OurName);    /* Gruppennamen eintragen */
  Generate_MDC(&msg,&p,&mdc);                     /* MDC generieren ... */
  Generate_Sign(&mdc,&msg.sign_r,&msg.sign_s,&x); /* ... und Nachricht unterschreiben */

  /*************  Machricht abschicken, Antwort einlesen  *******************/
  if (Transmit(con,&msg,sizeof(msg))!=sizeof(msg)) {
    fprintf(stderr,"Fehler beim Senden des 'ReportRequest': %s\n",NET_ErrorText());
    exit(20);
  }

  if (Receive(con,&msg,sizeof(msg))!=sizeof(msg)) {
    fprintf(stderr,"Fehler beim Empfang des 'ReportResponse': %s\n",NET_ErrorText());
    exit(20);
  }


  /******************  Überprüfen der Dämon-Signatur  ***********************/
  printf("Nachricht vom Dämon:\n");
  for (cnt=0; cnt<msg.body.ReportResponse.NumLines; cnt++) {
    printf("\t%s\n",msg.body.ReportResponse.Report[cnt]);
  }

  Generate_MDC(&msg,&p,&mdc);
  ok=Verify_Sign(&mdc,&msg.sign_r,&msg.sign_s,&Daemon_y);
  if (ok) printf("Dämon-Signatur ist ok!\n");
  else printf("Dämon-Signatur ist FEHLERHAFT!\n");

  /*>>>>                                      <<<<*
   *>>>> AUFGABE: Fälschen der Dämon-Signatur <<<<*
   *>>>>                                      <<<<*/

   printf("Sende Nachricht an Demon zurück...\n");
  if (!(con=ConnectTo(OurName,DAEMON_NAME))) {
    fprintf(stderr,"Kann keine Verbindung zum Daemon aufbauen: %s\n",NET_ErrorText());
    exit(20);
  }

  strcpy(msg.body.VerifyRequest.Report[0], "Der Teilnehmer rilokru die erforderliche Punktezahl weit absolut übertroffen.");
  strcpy(msg.body.VerifyRequest.Report[1], "Schein her! Diese Auskunft ist elektronisch unterschrieben und daher gültig --- gez. Sign_Daemon");

  msg.typ = VerifyRequest;
  if (Transmit(con,&msg,sizeof(msg))!=sizeof(msg)) {
    fprintf(stderr,"Fehler beim Senden des 'VerifyRequest': %s\n",NET_ErrorText());
    exit(20);
  }

  if (Receive(con,&msg,sizeof(msg))!=sizeof(msg)) {
    fprintf(stderr,"Fehler beim Empfang des 'VerifyResponse': %s\n",NET_ErrorText());
    exit(20);
  }
  printf("VerifyReponse vom Dämon:\n");
  
  printf("\t%s\n",msg.body.VerifyResponse.Res);
/*
  VerifyRequest vr;
  vr.NumLines = 0; 
  
  if (Transmit(con,&msg,sizeof(msg))!=sizeof(msg)) {  */
  return 0;
}


