# simple makefile

CFLAGS=-g -Wall -Wformat -Werror -I../messagelib
LFLAGS=-L../messagelib -liam-messaging -lcrypto -lssl -lcurl -lm -lpthread -luuid
DEPS=../messagelib/libiam-messaging.a
TESTS=test_msg test_crypt sigtest

all:	$(TESTS)

.c.o:	$(DEPS)
	$(CC) -g -c $(CFLAGS) $(@:.o=.c)

test_msg:	test_msg.o $(DEPS)
	cc -g -o test_msg test_msg.o $(LFLAGS)
	
test_crypt:	test_crypt.o $(DEPS)
	cc -g -o test_crypt test_crypt.o $(LFLAGS)
	
sigtest:	sigtest.o $(DEPS)
	cc -g -o sigtest sigtest.o $(LFLAGS)
	
clean:
	rm -f *.o  $(TESTS)
