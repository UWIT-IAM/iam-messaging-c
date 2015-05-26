/* ========================================================================
 * Copyright (c) 2012 The University of Washington
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


/* SNS message receiver: fcgi main */

#include "fcgi_stdio.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

#include "aws_sns.h"
#include "iam_crypt.h"


/* http responses.  Essentually just the status code */

void sns_fcgi_response(int code, char *text) {
   char *st = "200 OK";

   /* caller errors */
   if (code==400) st = "400 Bad Request";
   else if (code==401) st = "401 Unauthorized";
   else if (code==403) st = "403 Forbidden";
   else if (code==404) st = "404 Not Found";
   else if (code==405) st = "405 Method Not Allowed";
   else if (code==406) st = "406 Not Acceptable";

   /* server errors */
   else if (code==500) st = "500 Internal Server Error";
   else if (code==501) st = "501 Not Implemented";
   else if (code==503) st = "503 Service Unavailable";

   printf("Status: %s\nContent-type: text/html\n\n\n%s\n", st, text?text:"");

}


/* main: handle http requests */

int sns_fcgi_main(int(*msg_handler)(SNSMessage*), int(*get_handler)()) {

   int status = 0;
   char *request_method;
   char *s;

   while (FCGI_Accept() >= 0) {

      request_method = getenv("REQUEST_METHOD");
      if (!request_method) {
         fprintf(stderr, "no request method?");
         sns_fcgi_response(400, NULL);
         FCGI_Finish();
         continue;
      }

      // pass along any GETs
      if (!strcmp(request_method, "GET")) {
         if (get_handler) (*get_handler)();
         else sns_fcgi_response(400, NULL);
         FCGI_Finish();
         continue;
      }

      // get the message
      s = getenv("CONTENT_LENGTH");
      if (s && *s) {
         int len = atoi(s);
         char *snsmsg = (char*) malloc(len+1);
         int nb = fread(snsmsg, 1, len, stdin);
         if (nb!=len) {
            fprintf(stderr, "sns post content len (%d) did not match data len (%d)", len, nb);
            free(snsmsg);
            sns_fcgi_response(400, NULL);
            FCGI_Finish();
            continue;
         }
         snsmsg[nb] = '\0';
         status = sns_processSnsMessage(snsmsg, msg_handler);
         sns_fcgi_response(status, NULL);
         free(snsmsg);
      }

      FCGI_Finish();
   }
   exit (0);
}


