CC = gcc
LD = gcc
CFLAGS = -W -Wall -O4
LDFLAGS =

OBJS = cryptolib.o util.o
HEADERS = cryptolib.h util.h

all: nfc-cryptorf

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

nfc-cryptorf: nfc-cryptorf.c $(OBJS)
	$(LD) $(CFLAGS) $(LDFLAGS) -o $@ $< $(OBJS) -lnfc

clean:
	rm -f $(OBJS) nfc-cryptorf
