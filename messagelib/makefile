# makefile for src

CFLAGS=-g -Wall -Wformat -Werror 
# LFLAGS=-L. -liam_msg -lcrypto -lssl -lcurl -lm -lpthread
INCL_DEP=aws_sns.h  aws_sqs.h  azure.h  cJSON.h  iam_crypt.h  iam_msg.h


DEST=$(INSTALL_ROOT)
DEST_LIB=$(DEST)/lib
DEST_INC=$(DEST)/include

all:	libmessaging.a 

.c.o:	$(INCL_DEP)
	$(CC) -c $(CFLAGS) $(@:.o=.c)

libmessaging.a:	$(INCL_DEP) cJSON.o aws_sns.o aws_sqs.o iam_crypt.o iam_msg.o azure.o
	ar -rc libmessaging.a cJSON.o aws_sns.o aws_sqs.o iam_crypt.o iam_msg.o azure.o

install:	libmessaging.a
	cp libmessaging.a $(DEST_LIB)
	cp $(INCL_DEP) $(DEST_INC)
clean:
	rm -f *.o *.a 
