# Makefile dello sniffer per ilvoip
CC		=	gcc
LIBS		=	-lpcap
CFLAGS		=	-Wall
PROG		=	sniffex
SRC			=	sniffex.c
all:	sniffex.c voip.c 		
	$(CC) $(CFLAGS) -o $(PROG) -g $(SRC) $(LIBS)
clean:	
	rm -f sniffex *~ #*
