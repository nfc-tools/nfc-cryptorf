CC = gcc
LD = gcc
CFLAGS = -W -Wall -O4
LDFLAGS =

OBJS = cryptolib.o util.o
HEADERS = cryptolib.h util.h

all: $(OBJS) crf

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

% : %.c $(OBJS)
	$(LD) $(CFLAGS) $(LDFLAGS) -o $@ $< $(OBJS)

crf: crf.c $(OBJS)
	$(LD) $(CFLAGS) $(LDFLAGS) -o crf $< $(OBJS) -lnfc


clean:
	rm -f $(OBJS) $(EXES) crf
