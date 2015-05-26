/* ========================================================================
 * Copyright (c) 2013 The University of Washington
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

/* Recv UW message from aws */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iam_crypt.h"
#include "iam_msg.h"
#include "aws_sqs.h"

#include "cJSON.h"

char *prog;

void usage() {
   fprintf(stderr, "usage: %s [-v] [-n count] [-c cfg_file] \n", prog);
   exit (1);
}

int main(int argc, char **argv) {
   
   char *cfgfile = "demo.conf";
   int ntest = 5;
   int verbose = 0;

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
           break;
        case 'n':
           if (--argc<=0) usage();
           char *s = (++argv)[0];
           ntest = atoi(s);
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
  fprintf(stderr, "%d messages\n", nm);
  
  nm = sqs_getNumMessages(ctx);
  fprintf(stderr, "%d messages\n", nm);

  int n;
  for (n=0;n<ntest;n++) {
     IamMessage *msg = iam_msgRecv(ctx);
     if (msg) {
        if (msg->error) {
           printf("aws error %d: %s\n", msg->error, msg->message);
           iam_freeIamMessage(msg);
           break;
        }
        printf("message received: type: %s\n", msg->messageType);
        if (verbose) {
           printf("uuid: %s\n", msg->uuid);
           printf("sent: %s\n", msg->timestamp);
           printf("sender: %s\n", msg->sender);
           printf("contentType: %s\n", msg->contentType);
           printf("context: [%s]\n", msg->messageContext);
           printf("message: [%s]\n", msg->message);
        }
        iam_freeIamMessage(msg);
     } else {
        printf("no more messages\n");
        break;
     }
     // sleep(60);
  }
  printf("%d processed\n", n);
  exit (0);
}


