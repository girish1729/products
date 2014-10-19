OBJ = scmailer smtprelay *.o smtprelay testpq*
LDFLAGS+= -lpq -L/usr/local/lib
CFLAGS+= -I/usr/local/include -I/usr/local/include/postgresql -Wall -Wstrict-prototypes -g 

all:  $(OBJ)

scmailer: scmailer.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@
#smtprelay: smtprelay.c spfsc.c p0f-query.h
	#$(CC) $(CFLAGS)  -c spfsc.c -o spfsc.o
smtprelay: smtprelay.c  p0f-query.h
	$(CC) $(CFLAGS) -c smtprelay.c -o smtprelay.o
	$(CC) $(LDFLAGS) smtprelay.o  -o smtprelay
install:
	cp scmailer smtprelay /usr/local/bin/

clean:
	rm -rf $(OBJ) *.core $(OBJ)
