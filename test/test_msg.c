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

/* create/parse messages - allow multiple executions for valgrind */

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
   fprintf(stderr, "usage: %s [-c cfg_file] [-t text_file] [-n num_cycles] [-9 i9n_testname] \n", prog);
   exit (1);
}

int main(int argc, char **argv) {
   
   char *cfgfile = "test.conf";
   int lim = 1;
   char *limt;
   char *i9nfile = NULL;
   char *textfile = "mockdata/sigtest.txt";

   char *vers = "UWIT-2";   // assignments for v2 messages
   char *cryptid = "testcrypt2";

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
           break;
        case 't':
           if (--argc<=0) usage();
           textfile = (++argv)[0];
           break;
        case '9':
           if (--argc<=0) usage();
           i9nfile = (++argv)[0];
           break;
        case '1':
           vers = "UWIT-1";
           cryptid = "testcrypt1"; // crypt key is specific to the version
           break;
        case 'n':
           if (--argc<=0) usage();
           limt = (++argv)[0];
           lim = atoi(limt);
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

   printf("%d tests, vers=%s\n", lim, vers);
   int n=0;
   int i;
   char *sigid = "testsig1";

   /* create a signed and excrypted message */
   char *emsg = NULL;
   char *emsg_sav;
   if (textfile!=NULL) {
      char *msg_txt = iam_getFile(textfile);
      for (i=0; i<lim; i++) {
         IamMessage *msg = iam_newIamMessage();
         msg->version = strdup(vers);
         msg->contentType = strdup("json");
         msg->messageContext = strdup("some-message-context");
         msg->messageType = strdup("test");
         msg->message = strdup(msg_txt);
         msg->sender = strdup("iam-messaging-c");
         emsg = iam_msgEncode(msg, cryptid, sigid);
         // printf("emsg=%s\n", emsg);
         if (lim==1 && i9nfile!=NULL) {
            char *fname = (char*) malloc(strlen(i9nfile)+20);
            char *b64 = iam_dataToBase64(emsg, strlen(emsg));
            sprintf(fname, "%s.enc", i9nfile); 
            FILE *fp = fopen(fname , "w");
            fputs(b64, fp);
            fclose(fp);
            sprintf(fname, "%s.txt", i9nfile); 
            fp = fopen(fname , "w");
            fputs(msg_txt, fp);
            fclose(fp);
            free(b64);

         }
         if (i==0) emsg_sav = strdup(emsg);
         free(emsg);
         iam_freeIamMessage(msg);
      }
      free(msg_txt);
   }

   // printf("emsg_sav = %s\n", emsg_sav);
  
   /* Parse a signed and encrypted message */

  char *s = emsg_sav;
  for (i=0;i<lim;i++) {
     s = strdup(emsg_sav);
     IamMessage *msg = iam_msgParse(s);
     if (!msg) {
         fprintf(stderr, "message parse failed, i=%d\n", i);
         exit (1);
     }
     // printf ("n=%d, suvccess\n", i);
     iam_freeIamMessage(msg);
     n++;
     if ((n/10000)*10000 == n) printf(".");
  }
  free(emsg_sav);
  exit (0);
}


