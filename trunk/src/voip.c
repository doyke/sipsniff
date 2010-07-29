#include "voip.h"

//dichiarazione delle strutture utili per fare i conteggi
struct lista *li;
struct chiamata *ch;
struct info *in;


// se si embedda dentro sniffex il metodo main và commentato, serve solo per prova
/*
  int main(int argc, char *argv[]) {
  u_char str[] ="SIP/2.0 300 Trying\nVia: SIP/2.0/UDP 212.97.59.76:5061;branch=z9hG4bK900b.213a2681.0\nVia: SIP/2.0/UDP 212.97.59.77:5060;branch=z9hG4bK069244bd;rport=5060\nFrom: \"0500988207\" <sip:0500988207@sip.messagenet.it>;tag=as793b5f9a\nTo: <sip:06916502204@212.97.59.76:5061>;tag=380501218\nContact: <sip:5324152@192.168.178.20:5060>\nRecord-Route: <sip:212.97.59.76:5061;lr=on;ftag=as793b5f9a>\nCall-ID: 1ea78066561c762a1f6a36af357cefae@sip.messagenet.it\nCSeq: 102 INVITE";
  u_char *ptr;
  strcpy(li->call[0]->theinfo->callid,"jifhiavifrj9804j");
  ptr=str;
  //printf("%s\n",str);
  leggi_UDP(ptr);

  printf (" pacchetti=%d\t richiesta=%d\t risposta= %d\t invites=%d\t m1=%d\n",t.pacchetti,t.richieste,t.risposte,t.invites,t.m1);
  printf ("callid 0 %s\n",li->call[0]->theinfo->callid);
  printf ("1 - callid %s\t from %s\n",li->call[1]->theinfo->callid,li->call[1]->theinfo->numero);


  return 0;
  }
*/
void leggi_UDP(const u_char *data)
{
  /********* Informaœoni fisse per il pacchetto udp       ****/


  static int count_UDP=1; //conta i pacchetti udp
  struct udphdr *udp_hdr=(struct udphdr *)data;

  // UDP header e'sempre lungo 8 byte
  //queste info vanno decomentate quando il codice non è in prova cioè funziona in sniffex.c

  int data_length=ntohs(udp_hdr->uh_ulen) - 8;
  //char *string_data=NULL; per ora non serve

  // queste sono le porte per il mio client sip cioè se non è un pacchetto sip non m'interessa
  // si sarebbe potuto fare anche nelle espressioni dello sniffer ma ho voluto mettere qui il controllo
  int sport=ntohs(udp_hdr->uh_sport),dport=ntohs(udp_hdr->uh_dport);
  if ( !(sport==5061 || sport==5060 || dport==5061 || dport==5060)) return;

  printf("***** UDP Datagram *****\n");
  printf("Source port: %d  ",ntohs(udp_hdr->uh_sport));
  printf("Destination port: %d  ",ntohs(udp_hdr->uh_dport));
  printf("\tLunghezza pacchetto: %d\n",ntohs(udp_hdr->uh_ulen));

  printf ("Lunghezza %d\n",data_length);
  if (data_length<=200) return; //un pacchetto così corto non contiene dai miei test dati che possono servire
  //ho analizzato diversi pacchetti sip e il minore che ho trovato aveva una lunghezza superiore a 300, quindi scartanto questi non dovremmo perdere dati importanti per noi

  int caratteri=0;const int max_char_possibili=50;//se ci sono troppi caratteri prima del nome del metodo non è un pacchetto sip
  // ALL'INIZIO DEL PACCHETTO CI sono dei caratteri che non fanno parte del messaggio e quindi vanno eliminati
  while(isprint(*data)==0 && (caratteri<max_char_possibili)) // questo while elimina i caratteri non stampabili
    {	//isprint ritorna zero se non è stampabile
      data++;caratteri++;
    }


  while(isupper(*data)==0 && (caratteri<max_char_possibili)) // il primo carattere deve essere sicuramente un carattere maiuscolo
    { //la isupper ritorna zero se non è maiuscola
      data++;caratteri++;
    }
  if(caratteri==max_char_possibili)
    return; //non è un pacchetto sip se andasse avanti si rischierebbe un errore


  //printf("Dati passati:%s\n",data);

  //questo blocco serve per eliminare i caratteri che sono maiuscoli e non sono del metodo
  int i;int flag=0;int fine=1;
  while(fine==1){
    fine=1;
    for(i=0;i<NUM_MET;i++){
      if(		(*data==metodi[i][0]) && (*(data+1)==metodi[i][1]) )//se matcha le prime due lettere è quasi sicuramente il nome di un metodo
	{	flag=1;fine=0;break;}
    }
    if(flag==0){
      data++;
    }
  }
  //fine dei blocchi di controllo per i caratteri che non dovrebbero stare nel messaggio


  //*** recupera la callid e la pone in callid
  char callid[40];
  char from[20];
  //questa var d'appoggio serve per eliminare alcuni warning facendo il cast del pacchetto
  char search_data[1000];
  strcpy(search_data,(char *)data);
  search_data[999]='\0';//se dovesse superare la lunghezza per evitare errori
  //troviamo la callid del pacchetto che stiamo analizzando
  strcpy(callid,find_generic(search_data,"Call-ID:",' ',"@"));
  // vediamo se ne esiste già una

  struct chiamata *acall=givecallid(callid);
  // se non esiste la si crea e si mette il campo from

  if(acall==NULL){
    strcpy(from,find_generic(search_data,"From:",'"',"\""));
    acall=creacall(callid,from);
  }
  //	ora si possono fare le operazioni di conteggio

  /* bug risolto nel metodo got_packet
  //Si è riscontrato un bug se il puntatore data è troppo grande
  u_char appdata[1000];
  strcpy(appdata,data);
  appdata[999]='\0';
  data=appdata;
  //in questo modo superiamo l'errore
  */

  //**** IL CODICE SOTTOSTANTE ANALIZZA E FA I CONTEGGI PER RICHIESTA E RISPOSTA ***********
  char met[20];
  i=0;
  while(*data!= ' '){
    met[i++]=*data++;//in questo modo mettiamo la prima parola che non Ë interrotta da spazi dentro met,
    //puo' essere sia il nome del metodo che la versione di sip
  }
  met[i]='\0';

  //**** RISPOSTA *****
  if (strcmp(met,metodi[NUM_MET-1])==0){ // per esempio la risposta SIP/2.0 100 Trying
    t.pacchetti++;t.risposte++; //il totale delle risposte e delle richieste dei pacchetti
    acall->count->pacchetti++;acall->count->risposte++;//il totale per quella chiamata
    data++;//questo è lo spazio dopo il 2.0
    char cod[4]; // questo è il codice nel nostro caso 100
    cod[0]=*data++;
    cod[1]=*data++;
    cod[2]=*data++;
    cod[1]='\0';//a noi interessa solo il primo valore del codice quindi facciamo un cast
    int codice=atoi(cod);
    //t sono i tolali acall->count sono invece relativi a quella chiamata
    switch(codice){ // con questo switch aumentiamo il contatore del tipo di messaggio
    case 1:
      t.m1++;
      acall->count->m1++;
      break;
    case 2:
      t.m2++;
      acall->count->m2++;
      break;
    case 3:
      t.m3++;acall->count->m3++;
      break;
    case 4:
      t.m4++;acall->count->m4++;
      break;
    case 5:
      t.m5++;acall->count->m5++;
      break;
    default :
      break;
    }
  }
  else  //**** RICHIESTA ******
    {	// per capire questo codice che è la richiesta leggere prima quello della risposta sovrastante
      int f=trova_met(met);
      if (f!=-1){ //se non restituisce un codice d'errore è un metodo sip
	t.pacchetti++;t.richieste++;
	acall->count->pacchetti++;acall->count->richieste++;
	switch(f) {
	case INVITE:
	  t.invites++; acall->count->invites++;
	  break;
	case ACK:
	  t.ack++; acall->count->ack++;
	  break;
	case BYE:
	  t.bye++; acall->count->bye++;
	  break;
	case OPTIONS:
	  t.options++; acall->count->options++;
	  break;
	case CANCEL:
	  t.cancel++; acall->count->cancel++;
	  break;
	case M_REGISTER:
	  t.m_register++; acall->count->m_register++;
	  break;
	}
      }
    }
  count_UDP++;
}


int trova_met(char met [])
{
  int i;
  for(i=0;i<NUM_MET-1;i++)
    if (strcmp(metodi[i],met)==0)
      return i;
  return -1;
}
/* il vecchio trova metodo
   int trova_met(char met [])
   {
   if (strcmp(met,"INVITE")==0)
   return INVITE;
   if (strcmp(met,"ACK")==0)
   return ACK;
   if (strcmp(met,"BYE")==0)
   return BYE;
   if (strcmp(met,"OPTIONS")==0)
   return OPTIONS;
   if (strcmp(met,"CANCEL")==0)
   return CANCEL;
   if (strcmp(met,"REGISTER")==0)
   return M_REGISTER;
   return -1;
   }
*/
struct chiamata *givecallid(char *idcall){
  int i;
  if (li==NULL) inizializzastuct();
  for(i=0;i<NUM_CONT_CALLS;i++){// da bus error se non sono stati inizializzati tutti quanti i num_cont_calls
    if(strcmp(li->call[i]->theinfo->callid,idcall)==0)
      return li->call[i];
  }
  return NULL;
}

struct chiamata *creacall (char *acallid, char * afrom){
  int i;
  for(i=0;i<NUM_CONT_CALLS;i++){
    if(strcmp("",li->call[i]->theinfo->callid)==0){
      strcpy(li->call[i]->theinfo->callid,acallid);
      strcpy(li->call[i]->theinfo->numero,afrom);
      //printf("%s \n %s\n",li->call[i]->theinfo->callid,li->call[i]->theinfo->numero);
      return li->call[i];
    }
  }
  return NULL;
}
void inizializzastuct (){
  li=(struct lista *) malloc (sizeof(struct lista));
  int i;
  for (i=0;i<NUM_CONT_CALLS;i++){
    li->call[i]=(struct chiamata *) malloc (sizeof(struct chiamata));
    li->call[i]->theinfo=(struct info *) malloc (sizeof(struct info));
    li->call[i]->count=(struct total *) malloc (sizeof(struct total));
    //queste info non funzionano se non vengono inizializzate, solo per il primo contatore
    li->call[i]->count->pacchetti=li->call[i]->count->m1=li->call[i]->count->m2=li->call[i]->count->m_register=li->call[i]->count->cancel=0;
  }
}

char *find_generic(char *data_original,char start[],char prev,char post[]){
  char met[70];
  char delims[] = "\n";
  char *result = NULL;
  char data[1000];
  strcpy(data,data_original);
  result = strtok( data, delims );
  while( result != NULL ) {// dentro il ciclo otteniamo il risultato riga per riga
    if(strncmp(result,start,strlen(start))==0) {
      sprintf( met,"%s\n", result );
      break;
    }
    result = strtok( NULL, delims );
  }

  //per levare i caratteri all'inizio elimina tutti i caratteri fino allo spazio
  char *end;
  end=strchr(met,prev);
  if(end==NULL) return ""; // questo è un problema con le operazioni di register quando si apre x-lite dopo lo sniffer, perchè il campo è così composto From: Giuseppe B. <sip:5324152@sip.messagenet.it> quindi non dalle consuete "numero" che cera problemi al parsing
  end++;
  // per levare i caratteri alla fine
  char tmpcallid[40];
  strncpy(tmpcallid,end,strcspn(end,post));
  tmpcallid[strcspn(end,post)]='\0'; //terminiamo la stringa dove finiscono le info interessanti
  //il puntatore p serve per eliminare un warning
  char *p=tmpcallid;
  return p;
}
