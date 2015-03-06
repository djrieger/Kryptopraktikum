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

static int Verify_Sign(const_longnum_ptr mdc,const_longnum_ptr r,const_longnum_ptr s,const_longnum_ptr y)
  {
    const_longnum_ptr p_constptr = &p;
    const_longnum_ptr w_constptr = &w;
    longnum result, result_right;
    LInitNumber(&result, NBITS(&p), 0);
    LInitNumber(&result_right, NBITS(&p), 0);
    
    LModMultExp(y, r, r, s, &result, p_constptr);

    LModExp(w_constptr, mdc, &result_right, p_constptr);

    return LONGNUM_GET_LONG(&result, 0) == LONGNUM_GET_LONG(&result_right, 0);
  }


/*
 * Generate_Sign(m,r,s,x) : Erzeugt zu der MDC M eine El-Gamal-Signatur 
 *    in R und S. X ist der private Schlüssel
 */

static void Generate_Sign(const_longnum_ptr m, longnum_ptr r, longnum_ptr s, const_longnum_ptr x)
  {
    printf("bits=%d\n", NBITS(&p));
    printf("p=%lu\n", LONGNUM_GET_LONG(&p, 0));
    printf("w=%lu\n", LONGNUM_GET_LONG(&w, 0));
    printf("x=%lu\n", LONGNUM_GET_LONG(x, 0));
    printf("m=%lu\n", LONGNUM_GET_LONG(m, 0));
    
    int flags = 0;
    longnum k, pMinusOne;
    longnum ggt, US, VS;
    const_longnum_ptr k_constptr;
    LInitNumber(&pMinusOne, NBITS(&p), flags);
    LInitNumber(&k, NBITS(&p), flags);
    LInitNumber(&ggt, NBITS(&p), flags);
    LInitNumber(&US, NBITS(&p), flags);
    LInitNumber(&VS, NBITS(&p), flags);
    int sign;

    long pAsLong = LONGNUM_GET_LONG(&p, 0);
    LInt2Long(pAsLong - 1, &pMinusOne);
    const_longnum_ptr pMinusOneConstPtr = &pMinusOne;

    // calculate k
    do {
      // generate random number k (k < p - 1)
      LRand(pMinusOneConstPtr, &k);
      k_constptr = &k;      
      LggT(k_constptr, pMinusOneConstPtr, &ggt, &US, &VS, &sign);
    } while (!LIsOne(&ggt));

    printf("k=%lu\n", LONGNUM_GET_LONG(&k, 0)); 

    const_longnum_ptr w_constptr = &w;
    const_longnum_ptr p_constptr = &p;
    LModExp(w_constptr, k_constptr, r, p_constptr);
    printf("r = %lu\n", LONGNUM_GET_LONG(r, 0));
    printf("w^k mod p = %lu^%lu mod %lu\n", LONGNUM_GET_LONG(&w, 0), LONGNUM_GET_LONG(&k, 0), LONGNUM_GET_LONG(&p, 0));
    // TODO: r eigentlich falsch, größer als es durch Modulo p sein sollte

    LInvert(&k, pMinusOneConstPtr);

    long r_long = LONGNUM_GET_LONG(r, 0);
    long x_long = LONGNUM_GET_LONG(x, 0);
    long m_long = LONGNUM_GET_LONG(m, 0);
    
    longnum a_longnum;
    LInitNumber(&a_longnum, NBITS(&p), flags);
    LInt2Long(m_long - r_long * x_long, &a_longnum);
    const_longnum_ptr a_constptr = &a_longnum;

    LModMult(a_constptr, k_constptr, s, pMinusOneConstPtr);
    printf("s = %lu\n", LONGNUM_GET_LONG(s, 0));
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
  return 0;
}


