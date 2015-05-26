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

char *prog;
int debug = 0;

void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] [-m message]\n", prog);
   exit (1);
}

cJSON *config;
int err = 0;

 
// signature test
int azure_sig_test() {
   char *et;
   char *dt;
   
   char *pt = "https%3a%2f%2ffox-test-1-ns.servicebus.windows.net%3a443%2ffox-test-1%2fmessages\n1430175863";
   char *skey = "J4bCgbFK05akN6g8TWgG6PsyYShJYf9iprcVoaqR4wY=";
   if (debug) {
      printf(" > sig text: [%s]\n", pt);
      printf(" > sig key:  [%s]\n", skey);
   }

   // sign

   char *sig = iam_computeAzureSignature256(skey, pt);
   char *sigurl = iam_getSignUrl(skey);
   if (debug) {
      printf(" > sig=[%s]\n", sig);
      printf(" > url=[%s]\n", sigurl);
   }
 
}


main(int argc, char **argv) {
   
   char *cfgfile = "azure.conf";

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
        case '?':
           usage();
        }
      }
   }

   printf("debug = %d\n", debug);

   iam_crypt_init();

   azure_sig_test();
}


