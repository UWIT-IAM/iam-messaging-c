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

cJSON *config;
int err = 0;

// base64 test

int base64_test(char *textfile) {
   char *dt;
   int ret = 1;
   
   char *pt = iam_getFile(textfile);
   if (debug) {
      printf(" > b64: plain: (%zu) [%s]\n", strlen(pt), pt);
   }

   char *b64 = iam_dataToBase64(pt, strlen(pt));
   if (debug) {
      printf(" > b64: base64: (%zu) [%s]\n", strlen(b64), b64);
   }

   dt = iam_base64ToText(b64);
   if (debug) {
      printf(" > b64: decoded: (%zu) [%s]\n", strlen(dt), dt);
   }

   if (strcmp(pt, dt)) {
      printf("base64 text fails\n");
   } else {
      if (debug) printf("base64 test OK\n");
      ret = 0;
   }
   free(pt);
   free(dt);
   free(b64);
   
   return ret;
}
   
   
// crypt test
int crypt_test(char *datafile) {

   char *iv = NULL;
   char *et = NULL;
   char *dt = NULL;
   int ret = 1;
   
   char *pt = iam_getFile(datafile);
   char *ckey = "testcrypt1";
   if (debug) {
      printf(" > plain text: [%s]\n", pt);
      printf(" > crypt key:  [%s]\n", ckey);
   }

   // encrypt the plain text with the crypt key
   iam_encryptText(ckey, pt, strlen(pt), &et, &iv);
   if (debug) {
      printf(" > et=[%s]\n", et);
      printf(" > iv=[%s]\n", iv);
   }

   // decrypt
   iam_decryptText(ckey, et, &dt, iv);
   if (debug) {
      printf(" > Drypt text: [%s]\n", dt);
   }
   free(iv);
   free(et);
   if (strcmp(pt, dt)) {
      printf("crypt text fails\n");
   } else {
      if (debug) printf("crypt test OK\n");
      ret = 0;
   }
   free(pt);
   free(dt);
   return ret;
}
   
 
// signature test
int sig_test(char *datafile) {
   
   char *pt = iam_getFile(datafile);
   char *skey = "testsig1";
   if (debug) {
      printf(" > sig text: [%s]\n", pt);
      printf(" > sig key:  [%s]\n", skey);
   }

   // sign

   char *sig = iam_computeSignature(pt, skey);
   char *sigurl = iam_getSignUrl(skey);
   if (debug) {
      printf(" > sig=[%s]\n", sig);
      printf(" > url=[%s]\n", sigurl);
   }
 
   // verify
   int v = iam_verifySignature(pt, sig, sigurl);
   if (debug) printf("sig verify = %d\n", v);
   if (v==0) printf("sig fails\n");

   free(pt);
   free(sig);
   return v;
}


void usage() {
   fprintf(stderr, "usage: %s [-c cfg_file] [-m message]\n", prog);
   exit (1);
}

int main(int argc, char **argv) {
   
   char *cfgfile = "test.conf";
   char *datafile = "mockdata/iammsg.1";
   int lim = 1;
   int i;

   prog = argv[0];
   while (--argc > 0) {
     argv++;
     if (argv[0][0] == '-') {
        switch (argv[0][1]) {
        case 'c':
           if (--argc<=0) usage();
           cfgfile = (++argv)[0];
           break;
        case 'f':
           if (--argc<=0) usage();
           datafile = (++argv)[0];
           break;
        case 'n':
           if (--argc<=0) usage();
           char *limt = (++argv)[0];
           lim = atoi(limt);
           break;
        case 'd':
           debug = 1;
           break;
        case '?':
           usage();
        }
      }
   }

   iam_msgInit(cfgfile);

   for (i=0; i<lim;i++) {
      base64_test(datafile);
      crypt_test(datafile);
      sig_test(datafile);
   }
   exit(0);
}


