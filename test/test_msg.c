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

/* Recv message and parse 1000000 times */

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
   fprintf(stderr, "usage: %s [-c cfg_file] [-d data_file] [-n num_cycles] \n", prog);
   exit (1);
}

int main(int argc, char **argv) {
   
   char *cfgfile = "test.conf";
   int lim = 1;
   char *limt;
   char *datafile = "mockdata/iammsg.0";

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
           if (--argc<=0) usage();
           datafile = (++argv)[0];
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

  printf("%d tests\n", lim);
  int n=0;
  int i;
  char *s = iam_getFile(datafile);
  for (i=0;i<lim;i++) {
     IamMessage *msg = iam_msgParse(s);
     if (!msg) {
         fprintf(stderr, "message parse failed, i=%d\n", i);
         exit (1);
     }
     iam_freeIamMessage(msg);
     n++;
     if ((n/10000)*10000 == n) printf(".");
  }
  exit (0);
}


