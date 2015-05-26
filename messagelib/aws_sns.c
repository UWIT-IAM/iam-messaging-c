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

/* Amazon SNS send and receive tools */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>

#include <curl/curl.h>
// #include <curl/types.h>
#include <curl/easy.h>

#include "cJSON.h"
#include "iam_crypt.h"
#include "aws_sns.h"

#define TRACE if(0)fprintf

// free an sns message
static void freeSNSMessage(SNSMessage *sns) {
   if (sns->messageId) free(sns->messageId);
   if (sns->type) free(sns->type);
   if (sns->subject) free(sns->subject);
   if (sns->timestamp) free(sns->timestamp);
   if (sns->topicArn) free(sns->topicArn);
   if (sns->message) free(sns->message);
   free(sns);
}

/* Process an SNS message:  
   - parse the components
   - verify the signature
   - base64 decode the message
 */

int sns_processSnsMessage(char *snsmsg, int(*msg_handler)(SNSMessage*)) {

   char *type;

   TRACE(stderr, "incoming message: \"%s\"\n", snsmsg);

   cJSON *snsroot = cJSON_Parse(snsmsg);
   if (!snsroot) {
      syslog(LOG_ERR, "sns bad json input: %s", snsmsg);
      return (400);
   }

   if (!(type=safeGetString(snsroot, "Type"))) {
      syslog(LOG_ERR, "sns no type: %s", snsmsg);
      cJSON_Delete(snsroot);
      return (400);
   }
   
   SNSMessage *sns = (SNSMessage*) malloc(sizeof(SNSMessage));
   memset(sns, '\0', sizeof(SNSMessage));
   sns->type = strdup(type);
   sns->messageId = safeDupString(snsroot, "MessageId");
   sns->subject = safeDupString(snsroot, "Subject");
   sns->timestamp = safeDupString(snsroot, "Timestamp");
   sns->topicArn = safeDupString(snsroot, "TopicArn");

   if (strcmp(type, "Notification")) {
      fprintf(stderr, "message (%s) not a notification\n", type);
      if (!strcmp(type, "SubscriptionConfirmation")) {
          fprintf(stderr, "message is the subscription confirmation: %s\n", snsmsg);
      }
      freeSNSMessage(sns);
      cJSON_Delete(snsroot);
      return (200);
   }

   // get the message content
   char *msg = safeGetString(snsroot, "Message");
   if (!msg) {
      syslog(LOG_ERR, "no message content");
      freeSNSMessage(sns);
      cJSON_Delete(snsroot);
      return (400);
   }

   TRACE(stderr, "message is: %s \n", msg);

   // verify the SNS signature
   char *vfytxt = (char*) malloc(strlen(msg) + 1024);
   sprintf(vfytxt, "Message\n%s\nMessageId\n%s\nSubject\n%s\nTimestamp\n%s\nTopicArn\n%s\nType\n%s\n",
       msg, sns->messageId, sns->subject, sns->timestamp, sns->topicArn, sns->type); 
   TRACE(stderr, "sigmsg: %s\n", vfytxt);
   int v = iam_verifySignature(vfytxt, safeGetString(snsroot, "Signature"), safeGetString(snsroot, "SigningCertURL"));
   if (v==0) syslog(LOG_ERR, "signature verify fails:  %d", v);
   sns->verified = v;
   free (vfytxt);

   sns->message = iam_base64ToText(msg);
   cJSON_Delete(snsroot);
   return ((*msg_handler)(sns));
}

static char *awsKey = NULL;
static char *awsKeyId = NULL;
static char *snsHost = NULL;
static char *e_snsArn = NULL;

static char *snsAction = "Publish";

/* publish a message to sns:
   - base64 encode the message
   - generate signature
   - send to SNS
   - returns aws http status
 */

// default host and arn ( from aws config file )
int sns_sendMessage(RestContext *ctx, char *sub, char *msg, int msgl) {
   return sns_sendMessageArn(ctx, sub, msg, msgl, snsHost, e_snsArn);
}

// user specified host and arn (urlencoded)
int sns_sendMessageArn(RestContext *ctx, char *sub, char *msg, int msgl, char *host, char *e_arn) {
   char *b64msg = iam_dataToBase64(msg, msgl);
   char *e_b64msg = iam_urlencode(b64msg);
   char *e_sub = iam_urlencode(sub);
   char *timestamp = iam_timestampNow();
   char *e_timestamp = iam_urlencode(timestamp);
   int bufl = strlen(e_b64msg)+strlen(e_sub)+1024;
   TRACE(stderr, "bufl=%d, b64msg=%zu, e_b64msg=%zu, e_sub=%zu, e_timestamp=%zu\n",
        bufl, strlen(b64msg), strlen(e_b64msg), strlen(e_sub), strlen(e_timestamp) );
   char *qs = (char*) malloc(bufl);
   char *qspost = (char*) malloc(bufl);
   // e_timestamp = "timetime";
   snprintf(qs, bufl,
      "AWSAccessKeyId=%s&Action=%s&Message=%s&SignatureMethod=HmacSHA256&SignatureVersion=2&Subject=%s&Timestamp=%s&TopicArn=%s",
      awsKeyId, snsAction, e_b64msg, e_sub, e_timestamp, e_arn);
   char *sigin = (char*) malloc(bufl);
   snprintf(sigin, bufl, "POST\n%s\n/\n%s", host, qs);
   char *sig = iam_computeAWSSignature256(awsKey, sigin);
   char *e_sig = iam_urlencode(sig);
   snprintf(sigin, bufl, "%s&Signature=%s", qs, e_sig);

   // compose the url
   snprintf(qspost, bufl, "http://%s/", host);
   TRACE(stderr, "bufl=%d, sigin=%zu, qspost=%zu\n", bufl, strlen(sigin), strlen(qspost));
   
   curl_easy_setopt(ctx->curl, CURLOPT_URL, qspost);
   curl_easy_setopt (ctx->curl, CURLOPT_POSTFIELDS, sigin );
   CURLcode status = curl_easy_perform(ctx->curl);
   if (status!=CURLE_OK) {
      return (600);
   }

   // get the response message
   char *rsp = ctx->mem->mem;
   char *s;
   /**
   if (strstr(rsp, "<PublishResponse")) {
      char rspmsg[512];
      if ((s=strstr(rsp, "<MessageId>"))) {
         strncpy(rspmsg, s+11, 511);
         rspmsg[511] = '\0';
         if ((s=strstr(s, "</MessageId>"))) *s = '\0';
      }
   }
   **/
   if (strstr(rsp, "<ErrorResponse")) {
      ctx->http_resp = 400; // not ok
      if ((s=strstr(rsp, "<Message>"))) {
         char *e;
         if ((e=strstr(s, "</Message>"))) *e = '\0';
         strncpy(ctx->error, s+9, CURL_ERROR_SIZE);
         ctx->error[CURL_ERROR_SIZE-1] = '\0';
      }
   }

   curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &ctx->http_resp);
   if (ctx->http_resp>=300) {
      syslog(LOG_ERR, "aws post of %s failed: %ld", qspost, ctx->http_resp);
      return (ctx->http_resp);
   }

   free(b64msg);
   free(e_b64msg);
   free(e_sub);
   free(timestamp);
   free(e_timestamp);
   free(qs);
   free(sigin);
   free(sig);
   free(e_sig);
   free(qspost);
   return (ctx->http_resp);
}


int sns_init(char *host, char *arn, char *key, char *keyId) {

   iam_crypt_init();
   snsHost = host;
   e_snsArn = iam_urlencode(arn);
   awsKeyId = keyId;
   awsKey = key;

   return (1);
}  
