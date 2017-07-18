# simple makefile

CFLAGS=-g -Wall -Wformat -Werror -I../messagelib
LFLAGS=-L../messagelib -lmessaging -lcrypto -lssl -lcurl -lm -lpthread -luuid
DEPS=../messagelib/libmessaging.a
TESTS=test_msg test_crypt 

all:	$(TESTS)

.c.o:	$(DEPS)
	$(CC) -c $(CFLAGS) $(@:.o=.c)

test_msg:	test_msg.o $(DEPS)
	cc -g -o test_msg test_msg.o $(LFLAGS)
	
test_crypt:	test_crypt.o $(DEPS)
	cc -g -o test_crypt test_crypt.o $(LFLAGS)
	
	
clean:
	rm -f *.o  $(TESTS)
