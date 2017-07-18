# simple makefile

CFLAGS=-Wall -Wformat -Werror -I../messagelib
LFLAGS=-L../messagelib -lmessaging -lcrypto -lssl -lcurl -lm -lpthread -luuid
DEPS=../messagelib/libmessaging.a
DEMOS=aws_send aws_recv thread_send azure_send azure_recv thread_recv aws_send_sqs

all:	$(DEMOS)

.c.o:	$(DEPS)
	$(CC) -c $(CFLAGS) $(@:.o=.c)

demo_recv.cgi:	demo_recv.cgi.o $(DEPS) sns_fcgi.o
	cc -g -o demo_recv.cgi demo_recv.cgi.o sns_fcgi.o $(LFLAGS) -lfcgi

aws_send:	aws_send.o $(DEPS)
	cc -g -o aws_send aws_send.o $(LFLAGS)
	
aws_send_sqs:	aws_send_sqs.o $(DEPS)
	cc -g -o aws_send_sqs aws_send_sqs.o $(LFLAGS)
	
aws_recv:	aws_recv.o $(DEPS)
	cc -g -o aws_recv aws_recv.o $(LFLAGS)
	
leaktest:	leaktest.o $(DEPS)
	cc -g -o leaktest leaktest.o $(LFLAGS)
	
thread_send:	thread_send.o $(DEPS)
	cc -g -o thread_send thread_send.o $(LFLAGS)
	
thread_recv:	thread_recv.o $(DEPS)
	cc -g -o thread_recv thread_recv.o $(LFLAGS)
	
azuresig:	azuresig.o $(DEPS)
	cc -g -o azuresig azuresig.o $(LFLAGS)
	
azure_send:	azure_send.o $(DEPS)
	cc -g -o azure_send azure_send.o $(LFLAGS)
	
azure_recv:	azure_recv.o $(DEPS)
	cc -g -o azure_recv azure_recv.o $(LFLAGS)
	
clean:
	rm -f *.o  $(DEMOS)
