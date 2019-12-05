# makefile for src

CFLAGS=-Wall -Wformat -Werror 
# LFLAGS=-L. -liam_msg -lcrypto -lssl -lcurl -lm -lpthread
INCL_DEP=aws_sns.h  aws_sqs.h  azure.h  cJSON.h  iam_crypt.h  iam_msg.h


DEST=$(INSTALL_DEST)
DEST_LIB=$(DEST)/lib
DEST_INC=$(DEST)/include/iam-messaging

all:	libiam-messaging.a 

.c.o:	$(INCL_DEP)
	$(CC) -g -c $(CFLAGS) $(@:.o=.c)

libiam-messaging.a:	$(INCL_DEP) cJSON.o aws_sns.o aws_sqs.o iam_crypt.o iam_msg.o azure.o
	ar -rc libiam-messaging.a cJSON.o aws_sns.o aws_sqs.o iam_crypt.o iam_msg.o azure.o

install:	libiam-messaging.a
	cp libiam-messaging.a $(DEST_LIB)
	mkdir --parents --mode=755 $(DEST_INC)
	cp $(INCL_DEP) $(DEST_INC)
clean:
	rm -f *.o *.a 
