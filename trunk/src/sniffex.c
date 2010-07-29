//In base a che interfaccia si sniffa bisogna cambiare il SIZE ETHERNET TRA LE PRIME RIGHE

// Le istruzioni di compilazione e di funzionamento sono alla fine del file

#define APP_NAME		"sniff"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#include "voip.c"
/*
  #include <signal.h> //
  #include <net/bpf.h> //
  #include <net/ethernet.h> //
  #include <netinet/ip.h> //
  #include <net/if_arp.h> //
  #include <netinet/ip_icmp.h> //
  #include <netinet/tcp.h> //
*/

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
//#define SIZE_ETHERNET 14 //valore originale per ethernet Ë 14 (eth0) , ho messo 4 (lo0) per l'interfaccia localhost preso da sniffer.c
int SIZE_ETHERNET;
/*se metto 14 per fare lo sniffer di localhost mi da invalid ip header riga 447 circa
  con 14 per en1 valore preseo sempre da sniffer non mi legge bene le pagine
*/

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define INVITE 0
#define ACK 1
#define BYE 2
#define OPTIONS 3
#define CANCEL 4
#define M_REGISTER 5

/* Ethernet header */
struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char  ip_tos;                 /* type of service */
  u_short ip_len;                 /* total length */
  u_short ip_id;                  /* identification */
  u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
  u_char  ip_ttl;                 /* time to live */
  u_char  ip_p;                   /* protocol */
  u_short ip_sum;                 /* checksum */
  struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
/* il vhl è il campo combinato di Version e Header */
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
// questa deve estrarre la dimensione del header
/* in questo caso fa un and bit a bit con il valore esadecimale 0f che se lo stampiamo come fatto in
   num-prove.c otteniamo 15 quindi in binario 00 00 11 11, perciò facendo un and puliamo il campo e
   restituiamo solo i 4 bit più a destra e non quelli a sinistra*/
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
// questa invece deve estrarre la versione di ip
/* dobbiamo estrarre i 4 bit più a sinistra quindi facciamo uno shift e gli altri 4 saranno 0 */

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;               /* source port */
  u_short th_dport;               /* destination port */
  tcp_seq th_seq;                 /* sequence number */
  tcp_seq th_ack;                 /* acknowledgement number */
  u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  /*bisogna restiruire solo i 4 bit più a sinistra quindi prima facciaco l'and con 0f che in
    bianario è 11 11 00 00  e poi spostiamo di 4 che visto che u_char è 8bit otteniamo la lunghezza*/
  u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;                 /* window */
  u_short th_sum;                 /* checksum */
  u_short th_urp;                 /* urgent pointer */
};

void leggi_UDP(const u_char *data);

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

int trova_met(char met []);

void
print_app_banner(void);

void
print_app_usage(char*);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

  printf("%s - %s\n", APP_NAME, APP_DESC);
  printf("%s\n", APP_COPYRIGHT);
  printf("%s\n", APP_DISCLAIMER);
  printf("\n");

  return;
}

/*
 * print help text
 */
void
print_app_usage(char *prog)
{

  printf("Usage: %s [interface]\n", prog);
  printf("\n");
  printf("Options:\n");
  printf("    interface    Listen on <interface> for packets.\n");
  printf("\n");

  exit(0);
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
  //le linee commetante servono per non stampare la parte esadecimale del pacchetto e concentrarsi solo sul testo
  int i;
  int gap;
  const u_char *ch;

  /* offset */
  //printf("%05d   ", offset);

  /* hex */
  ch = payload;
  for(i = 0; i < len; i++) {
    //	printf("%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    //	if (i == 7)
    //		printf(" ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    //	printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
      gap = 16 - len;
      for (i = 0; i < gap; i++) {
	//		printf("   ");
      }
    }
  //printf("   ");

  /* ascii (if printable) */
  ch = payload;
  for(i = 0; i < len; i++) {
    if (isprint(*ch))
      printf("%c", *ch);
    else
      printf(".");
    ch++;
  }

  //printf("\n");

  return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

  int len_rem = len;
  int line_width = 16;			/* number of bytes per line */
  int line_len;
  int offset = 0;					/* zero-based offset counter */
  const u_char *ch = payload;

  if (len <= 0)
    return;

  /* data fits on one line */
  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  /* data spans multiple lines */
  for ( ;; ) {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    print_hex_ascii_line(ch, line_len, offset);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width) {
      /* print last line and get out */
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

  return;
}

/*
 * dissect/print packet
 */


void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

  static int count = 1;                   /* packet counter */

  /* declare pointers to packet headers */
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const u_char *payload;                    /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;
  int istcp=1;

  printf("\nPacket number %d:\t", count);
  count++;
  //saltiamo i pacchetti 561 e 562 if (count == 562 || count == 563) return;
  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);
  /* il pacchetto passato come parametro che contiene tutta la struttura
     serializzata per prima cosa viene castato ad ethernet per poter operare */

  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  /* print source and destination IP addresses */
  printf("       From: %s\n", inet_ntoa(ip->ip_src));
  printf("         To: %s\n", inet_ntoa(ip->ip_dst));

  /* determina il protocollo se non Ë tcp ritorna altrimenti stampa il payload */
  switch(ip->ip_p) {
  case IPPROTO_TCP:
    printf("   Protocol: TCP\n");//Variante che non c'interessano i pacchetti tcp
    istcp=1; return;
    break;
  case IPPROTO_UDP:
    printf("   Protocol: UDP\n\n");
    istcp=0;
    break;//return;
  case IPPROTO_ICMP:
    printf("   Protocol: ICMP\n");
    return;
  case IPPROTO_IP:
    printf("   Protocol: IP\n");
    return;
  default:
    printf("   Protocol: unknown\n");
    return;
  }

  //l'if server se vogliamo visulizzare anche le info per i pacchetti tcp oltre agli udp
  if (istcp==1)
    {
      /*
       *  OK, this packet is TCP.
       */

      /* define/compute tcp header offset */
      tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      if (size_tcp < 20) {
	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	return;
      }

      printf("   Src port: %d\n", ntohs(tcp->th_sport));
      printf("   Dst port: %d\n", ntohs(tcp->th_dport));

      /* define/compute tcp payload (segment) offset */
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

      /* compute tcp payload (segment) size */
      size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

      /*
       * Print payload data; it might be binary, so don't just
       * treat it as a string.
       */
      printf("\n");
      if (size_payload > 0) {
	printf("   Payload (%d bytes):\n", size_payload);
	print_payload(payload, size_payload);
      }
    }
  else
    {
      // se passo alla mia funzione una costante di 1400 caratteri circa, anche se poi nella funzione la casto da errore quindi devo accorciarla prima
      if ( (int)strlen((char*)(packet + SIZE_ETHERNET + size_ip)) > 999)
	{
	  printf ("L=%d\n",(int)strlen((char*)(packet + SIZE_ETHERNET + size_ip)));
	  const u_char *d=packet + SIZE_ETHERNET + size_ip;
	  char unastr[1000];
	  strncpy(unastr, (char*)d,999);
	  const u_char *pacc=(u_char*)unastr;
	  leggi_UDP(pacc);
	}
      else leggi_UDP(packet + SIZE_ETHERNET + size_ip);
    }

  return;
}

int main(int argc, char **argv)
{

  char *dev = NULL;			/* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
  pcap_t *handle;				/* packet capture handle */

  char filter_exp[] = "ip";		/* filter expression [3] */
  struct bpf_program fp;			/* compiled filter program (expression) */
  bpf_u_int32 mask;			/* subnet mask */
  bpf_u_int32 net;			/* ip */
  int num_packets = -1;			/* number of packets to capture */

  print_app_banner();
  /*bisogna inizializzare i metodi che si possono chiamare*/
  strcpy(metodi[0],"INVITE");
  strcpy(metodi[1],"ACK");
  strcpy(metodi[2],"BYE");
  strcpy(metodi[3],"OPTIONS");
  strcpy(metodi[4],"CANCEL");
  strcpy(metodi[5],"REGISTER");
  strcpy(metodi[6],"SIP/2.0"); //questo metodo deve essere sempre l'ultimo del vettore altrimenti il programma non funziona
  //fine inizializzazione dei nomi di metodo

  /* check for capture device name on command-line */
  if (argc == 2) {
    if((!strcmp(argv[1], "-h")) || (!strcmp(argv[1], "-help")))
      print_app_usage(argv[1]);
    dev = argv[1];
  }
  else if (argc > 2) {
    fprintf(stderr, "error: unrecognized command-line options\n\n");
    print_app_usage(argv[1]);
    exit(EXIT_FAILURE);
  }
  else {
    /* find a capture device if not specified on command-line */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n",
	      errbuf);
      exit(EXIT_FAILURE);
    }
  }

  /* get network number and mask associated with capture device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
	    dev, errbuf);
    net = 0;
    mask = 0;
  }

  /* print capture info */
  printf("Device: %s\n", dev);
  printf("Number of packets: %d\n", num_packets);
  printf("Filter expression: %s\n", filter_exp);

  /* open capture device */
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if(!handle) handle = pcap_open_offline(dev, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  /* make sure we're capturing on an Ethernet device [2] */
  /*if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    //exit(EXIT_FAILURE);
    }
  */

  int link_layer,offset;
  //FACCIAMO IN MODO DA INDIVIDUARE IL LINK LAYER
  link_layer = pcap_datalink(handle);
  switch(link_layer)
    {
    case DLT_EN10MB:
      offset = 14;
      break;
    case DLT_NULL:
    case DLT_PPP:
      offset = 4;
      break;
    case DLT_SLIP:
      offset = 16;
      break;
    case DLT_RAW:
      offset = 0;
      break;
    case DLT_SLIP_BSDOS:
    case DLT_PPP_BSDOS:
      offset = 24;
      break;
    case DLT_FDDI:
      offset = 21;
      break;
    default:
      fprintf(stderr, "Error: Unknown Datalink Type: (%d)\n\n", link_layer);
      return -1;
    }
  printf ("link layer:%d\n",link_layer);
  printf ("offset: %d\n",offset);
  SIZE_ETHERNET=offset; //se usiamo l'identificazione del link layer automatica altrimenti ci sono i valori della define da decomenttare all'inizio, e questo và commentato

  //FINE IDENTIFICAZIONE DEL LINK LAYER

  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
	    filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
	    filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* now we can set our callback function */
  pcap_loop(handle, num_packets, got_packet, NULL); //richiama la funzione got_packet

  /* cleanup */
  pcap_freecode(&fp);
  pcap_close(handle);

  printf("\nCapture complete.\n");
  //printf (" pacchetti=%d\t richiesta=%d\t risposta= %d\t invites=%d\n",t.pacchetti,t.richieste,t.risposte,t.invites);

  printf ("\t***** CONTATORE TOTALE ******\n");
  printf ("PACCHETTI=%d\t RICHIESTE=%d\t RISPOSTE=%d\t SIP 1xx=%d\t SIP 2xx=%d\t SIP 3xx =%d\t SIP 4xx=%d\t SIP 5xx=%d\n",t.pacchetti,t.richieste,t.risposte,t.m1,t.m2,t.m3,t.m4,t.m5);
  printf ("INVITES=%d\t BYE=%d\t OPTIONS=%d\t	CANCEL=%d\t REGISTER=%d\t ACK=%d\n",t.invites,t.bye,t.options,t.cancel,t.m_register,t.ack);

  int j;
  if (li==NULL) printf ("\nNon ci sono state chiamate\n");
  else
    {	for(j=0;j<NUM_CONT_CALLS;j++){
      if (strcmp(li->call[j]->theinfo->callid,"")==0) break;
      printf("\t **** CHIAMATA N. %d ******************** \n",j+1);
      printf("CALL ID: %s\t DA: %s\n",li->call[j]->theinfo->callid,li->call[j]->theinfo->numero);
      printf ("PACCHETTI=%d\t RICHIESTE=%d\t RISPOSTE=%d\t SIP 1xx=%d\t SIP 2xx=%d\t SIP 3xx =%d\t SIP 4xx=%d\t SIP 5xx=%d\n",li->call[j]->count->pacchetti,li->call[j]->count->richieste,li->call[j]->count->risposte,li->call[j]->count->m1,li->call[j]->count->m2,li->call[j]->count->m3,li->call[j]->count->m4,li->call[j]->count->m5);
      printf ("INVITES=%d\t BYE=%d\t OPTIONS=%d\t	CANCEL=%d\t REGISTER=%d\t ACK=%d\n",li->call[j]->count->invites,li->call[j]->count->bye,li->call[j]->count->options,li->call[j]->count->cancel,li->call[j]->count->m_register,li->call[j]->count->ack);
    }
    }


  //stampa();

  return 0;
}

/* ***************************************************************************
 *
 * La dimensione del pacchetto ethernet è sempre di 14 bytes non dipende
 * ne dalla piattaforma ne dal compilatore utilizzato
 *
 *
 * La dimensione dell'headert ip in byte è il valore estratto dal campo
 * ip_vhl campo della struttura sniff_ip con la macro IP_HL quattro volte,
 * quattro volte per è in unità di 4 parole. Se il valore è minore di 20
 * allora abbiamo un pacchetto malformato.
 *
 *
 * Le dimensioni sono in parole quindi visto che noi operiamo su byte dobbiamo
 * moltiplicare per 4
 *
 * Per trovare quanto payload c'è , prendere la dimensione totale del campo ip_len
 * nella sniff_ip e controllare se la dimensione totale del campo è almeno 5 altrimenti
 * si ha un pacchetto malformato
 * Altrimenti sottrai ip_hl *4 da ip_len che ti dà la dimensione del segmento tcp incluso
 * l'header tcp. Se questo è del TH_OFF(tcp)*4 che è la lunghezza dell'header tcp in parole
 * di 32bytes allora hai un pacchetto tcp malformato (bisogna sempre controllare che il
 * TH_OFF(tcp)*4 è >= 5)
 * Altrimenti sottrai "TH_OFF(tcp)*4" da quello totale del ip_hl che ti da la dimensione
 * totale del pacchetto tcp
 *
 * Note that you also need to make sure that you don't go past the end
 * of the captured data in the packet - you might, for example, have a
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too
 * small for an IP header.  The length of the captured data is given in
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than
 * the length of the packet, if you're capturing with a snapshot length
 * other than a value >= the maximum packet size.
 * <end of response>
 *
 ****************************************************************************
 *
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 *
 * Estratto dal manuale del gcc
 * This enables all the warnings about constructions that some users consider questionable, and
 *	that are easy to avoid (or modify to prevent the warning), even in conjunction with macros
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 *
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */
