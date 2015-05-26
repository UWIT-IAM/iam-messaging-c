/* ========================================================================
 * Copyright (c) 2015 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/* Receive UW messages from aws ( threading test) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "iam_crypt.h"
#include "iam_msg.h"
#include "aws_sqs.h"

#include "cJSON.h"

char *prog;

char *cryptid = "iamcrypt1";
char *signid = "iamsig1";

void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] [-m max_messages_per_thread] [-t num_threads]\n", prog);
   exit (1);
}

int max_per_thread = 5;
int verbose = 0;

int tnum = 0;

/* Thread to receive messages  */

void *th_sqs_recv(void *arg) {

   int tn = tnum++;
   printf ("thread %d starting\n", tn);
   int i;
   int nm = 0;
   RestContext *ctx = iam_restContext();
   for (i=0;i<max_per_thread || max_per_thread==0;i++) {
      IamMessage *msg = iam_msgRecv(ctx);
      if (msg) {
         if (msg->error) {
            printf("aws error %d: %s\n", msg->error, msg->message);
            iam_freeIamMessage(msg);
            break;
         }
         if (verbose) {
            printf("message received: type: %s\n", msg->messageType);
            printf("sender: %s\n", msg->sender);
            printf("context: [%s]\n", msg->messageContext);
            printf("message: [%s]\n", msg->message);
         }
         iam_freeIamMessage(msg);
         nm++;
      } else {
         printf("no more messages\n");
         break;
     }
   }
   printf ("thread %d exiting, %d messages\n", tn, nm);
   iam_freeRestContext(ctx);
   pthread_exit(NULL);
}


int main(int argc, char **argv) {
   
   char *cfgfile = "demo.conf";
   char *s;

   int i;
   int nthread = 3;

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
           break;
        case 'm':
           if (--argc<=0) usage();
           s = (++argv)[0];
           max_per_thread = atoi(s);
           break;
        case 't':
           if (--argc<=0) usage();
           s = (++argv)[0];
           nthread = atoi(s);
           break;
        case 'v':
           verbose = 1;
           break;
        case '?':
           usage();
        }
      }
   }

   if (!iam_msgInit(cfgfile)) {
      fprintf(stderr, "config file error\n");
      exit(1);
   }

   RestContext *ctx = iam_restContext();
   int nm = sqs_getNumMessages(ctx);
   fprintf(stdout, "%d messages in the queue\n", nm);
   iam_freeRestContext(ctx);

   pthread_t *threads = (pthread_t*)malloc(sizeof(pthread_t) * nthread);
   for (i=0;i<nthread;i++) {
       char tht[8];
       sprintf(tht, "%d", i);
       pthread_attr_t pta;

       pthread_attr_init(&pta);
       pthread_create(&(threads[i]), &pta, th_sqs_recv, (void*) tht);
       
   }
   for (i=0;i<nthread;i++) {
       pthread_join(threads[i], NULL);
   }
   exit (0);
}


