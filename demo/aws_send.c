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

/* Send UW message to aws */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iam_crypt.h"
#include "iam_msg.h"
#include "aws_sns.h"

#include "cJSON.h"

char *prog;

void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] [-m message] [-f message_file] [-n num_msg] [-z] [-h host -a arn]\n", prog);
   fprintf(stderr, "         [ -s  signid] [-d cryptid] \n");
   fprintf(stderr, "         -z  ( no crypt )\n");
   fprintf(stderr, "         -n  ( def = 2 )\n");
   exit (1);
}

int main(int argc, char **argv) {
   
   char *message = "Hello, world, from c";
   char *cfgfile = "demo.conf";
   char *type = "uw-test-message";
   char *cryptid = "iamcrypt1";
   char *signid = "iamsig1";
   char *msgfile = NULL;
   char *host = NULL;
   char *arn = NULL;
   char *_arn = NULL;

   int i;
   int nsend = 2;

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
           nsend = atoi(s);
           break;
        case 'm':
           if (--argc<=0) usage();
           message = (++argv)[0];
           break;
        case 'f':
           if (--argc<=0) usage();
           msgfile = (++argv)[0];
           break;
        case 'd':
           if (--argc<=0) usage();
           cryptid = (++argv)[0];
           break;
        case 's':
           if (--argc<=0) usage();
           signid = (++argv)[0];
           break;
        case 'h':
           if (--argc<=0) usage();
           host = (++argv)[0];
           break;
        case 'a':
           if (--argc<=0) usage();
           _arn = (++argv)[0];
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
   if (_arn) arn = iam_urlencode(_arn);
   IamMessage *msg = iam_newIamMessage();
   msg->contentType = strdup("json");
   msg->messageContext = strdup("some-message-context");
   msg->messageType = strdup(type);
   if (msgfile) msg->message = iam_getFile(msgfile);
   else msg->message = strdup(message);
   if (!msg->message) {
      fprintf(stderr, "no message\n");
      exit (1);
   }
   msg->sender = strdup("iamtest-c");
   RestContext *ctx = iam_restContext();
   for (i=0;i<nsend;i++) {
      printf("sending %zu bytes\n", strlen(msg->message));
      if (host) iam_msgSendArn(ctx, msg, cryptid, signid, host, arn);
      else iam_msgSend(ctx, msg, cryptid, signid);
   }
   iam_freeIamMessage(msg);
   exit (0);
}


