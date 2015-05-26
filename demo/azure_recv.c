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

/* Tests */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iam_crypt.h"
#include "iam_msg.h"

#include "cJSON.h"

#include "azure.h"

char *prog;
int debug = 0;

void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] \n", prog);
   exit (1);
}

cJSON *config;
int err = 0;

 

int main(int argc, char **argv) {
   
   char *cfgfile = "demo.conf";
   int nrecv = 1;

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
           break;
        case 'd':
           debug = 1;
           break;
        case 'n':
           if (--argc<=0) usage();
           char *s = (++argv)[0];
           nrecv = atoi(s);
           break;
        case '?':
           usage();
        }
      }
   }

   iam_msgInit(cfgfile);

   int nr = 0;
   while (nrecv-- != 0) {
      AzureMessage *msg = azure_recvMessage("fox-test-1-ns", "fox-test-1", "fox-sub-1");
      if (!msg) continue;
      if (debug>0) printf ("azmsg[%s]\n", msg->msg);
      else printf(".");
      azure_deleteMessage(msg);
      nr++;
   }
   printf("\nreceived: %d\n", nr);
   exit (0);
}


