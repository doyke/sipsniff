
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>

//i codici che ho assegnato ai vari tipi di messaggi,corrisponde alla posizione del vettore nel main
#define INVITE 0
#define ACK 1
#define BYE 2
#define OPTIONS 3
#define CANCEL 4
#define M_REGISTER 5

#define NUM_MET 7 //dimensione dell'array
char metodi[NUM_MET][10];


// IL NUMERO DI CHIAMATE gestibili DEL SOFTWARE DI SIP
#define NUM_CONT_CALLS 5000

// le strutture per tenere i conteggi
struct lista {
  struct chiamata *call[NUM_CONT_CALLS];
};

struct chiamata{
  struct total *count;
  struct info *theinfo;
};

struct info{
  char callid [40];
  char numero [15];
};

struct total{
  int pacchetti;
  int richieste; int risposte;
  int m1; //messaggi di tipo SIP 1xx m2 SIP 2xx e successivi
  int m2; int m3; int m4; int m5;
  int invites;
  int bye;
  int options;
  int cancel;
  int m_register;
  int ack;
};

struct total t;
char tmpfrom[40];

void inizializzastuct ();
void leggi_UDP(const u_char *data);
int trova_met(char met []);
char *find_generic(char *data_original,char start[],char prev,char post[]);
struct chiamata *givecallid(char *idcall);
struct chiamata *creacall (char *, char *);
