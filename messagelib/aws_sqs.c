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

/* Amazon SQS send and receive tools */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include "cJSON.h"
#include "iam_crypt.h"
#include "aws_sqs.h"

#define TRACE if(0)fprintf

// free an sqs message
void freeSQSMessage(SQSMessage *sqs) {
   if (sqs->messageId) free(sqs->messageId);
   if (sqs->type) free(sqs->type);
   if (sqs->subject) free(sqs->subject);
   if (sqs->timestamp) free(sqs->timestamp);
   if (sqs->topicArn) free(sqs->topicArn);
   if (sqs->message) free(sqs->message);
   if (sqs->handle) free(sqs->handle);
   free(sqs);
}

/* Return an error message */
static SQSMessage *errSQSMessage(int code, char *msg) {
   SQSMessage *sqs = (SQSMessage*) malloc(sizeof(SQSMessage));
   memset(sqs, '\0', sizeof(SQSMessage));
   sqs->verified = code;
   sqs->message = strdup(msg);
   return (sqs);
}

/* Decode and verify an incoming sqs message  
   - parse the components
   - verify the signature
   - base64 decode the message
 */

static SQSMessage *newSQSMessage(char *sqsmsg, char *handle) {
   char *type;

   if (!sqsmsg) return (NULL);
   TRACE(stderr, "incoming message: [%s]\n", sqsmsg);
   TRACE(stderr, "incoming handle: [%s]\n", handle);

   if (*sqsmsg != '{') {
      SQSMessage *sqs = (SQSMessage*) malloc(sizeof(SQSMessage));
      memset(sqs, '\0', sizeof(SQSMessage));
      sqs->type = strdup("Event");
      sqs->messageId = iam_timestampNow();
      sqs->message = iam_base64ToText(sqsmsg);
      sqs->handle = strdup(handle);
      TRACE(stderr, "message is: %s \n", sqs->message);
      return (sqs);
   }

   cJSON *sqsroot = cJSON_Parse(sqsmsg);
   if (!sqsroot) {
      syslog(LOG_ERR, "aws_sqs bad json input: %s", sqsmsg);
      return (NULL);
   }

   if (!(type=safeGetString(sqsroot, "Type"))) {
      syslog(LOG_ERR, "sqs no type: %s", sqsmsg);
      cJSON_Delete(sqsroot);
      return (NULL);
   }
   TRACE(stderr, "message type: %s \n", type);
   
   SQSMessage *sqs = (SQSMessage*) malloc(sizeof(SQSMessage));
   memset(sqs, '\0', sizeof(SQSMessage));
   sqs->type = strdup(type);
   sqs->messageId = safeDupString(sqsroot, "MessageId");
   sqs->subject = safeDupString(sqsroot, "Subject");
   sqs->timestamp = safeDupString(sqsroot, "Timestamp");
   sqs->topicArn = safeDupString(sqsroot, "TopicArn");
   sqs->handle = strdup(handle);

   if (strcmp(type, "Notification") && strcmp(type, "UWEvent")) {
      syslog(LOG_INFO, "message (%s) not a notification or uw sqs", type);
      if (!strcmp(type, "SubscriptionConfirmation")) {
          syslog(LOG_INFO, "message is the subscription confirmation: %s", sqsmsg);
      }
      freeSQSMessage(sqs);
      cJSON_Delete(sqsroot);
      return (NULL);
   }

   // get the message content
   char *msg = safeGetString(sqsroot, "Message");
   if (!msg) {
      TRACE(stderr, "no message content\n");
      freeSQSMessage(sqs);
      cJSON_Delete(sqsroot);
      return (NULL);
   }

   TRACE(stderr, "message is: %s \n", msg);

   // verify the SNS signature
   char *vfytxt = (char*) malloc(strlen(msg) + 1024);
   sprintf(vfytxt, "Message\n%s\nMessageId\n%s\nSubject\n%s\nTimestamp\n%s\nTopicArn\n%s\nType\n%s\n",
       msg, sqs->messageId, sqs->subject, sqs->timestamp, sqs->topicArn, sqs->type); 
   TRACE(stderr, "sigmsg: %s\n", vfytxt);
   int v = iam_verifySignature(vfytxt, safeGetString(sqsroot, "Signature"), safeGetString(sqsroot, "SigningCertURL"));
   if (v==0) syslog(LOG_ERR, "signature verify fails:  %d", v);
   sqs->verified = v;
   free (vfytxt);

   sqs->message = iam_base64ToText(msg);
   TRACE(stderr, "message is: %s \n", sqs->message);

   cJSON_Delete(sqsroot);
   return (sqs);
}

static char *awsKey = NULL;
static char *awsKeyId = NULL;
static char *sqsUrl = NULL;
static char *sqsHost = NULL;
static char *sqsPath = NULL;

static char *sqsInfoAction = "GetQueueAttributes";
static char *sqsRecvAction = "ReceiveMessage";
static char *sqsDeleteAction = "DeleteMessage";

/* get queue info
 */

int sqs_getNumMessages(RestContext *ctx) {
   char *timestamp = iam_timestampNow();
   char *e_timestamp = iam_urlencode(timestamp);
   int bufl = 1024;
   char *qs = (char*) malloc(bufl);
   snprintf(qs, bufl,
      "AWSAccessKeyId=%s&Action=%s&AttributeName.1=All&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=%s",
      awsKeyId, sqsInfoAction, e_timestamp);
   char *sigin = (char*) malloc(bufl);
   snprintf(sigin, bufl, "GET\n%s\n%s\n%s", sqsHost, sqsPath, qs);
   char *sig = iam_computeAWSSignature256(awsKey, sigin);
   char *e_sig = iam_urlencode(sig);
   snprintf(sigin, bufl, "%s?%s&Signature=%s", sqsUrl, qs, e_sig);
   
   char *txt = iam_getPage(ctx, sigin);
   if (!txt) {
      long resp = iam_restContextResp(ctx);
      syslog(LOG_ERR, "aws getmsg failed: %s", iam_restContextError(ctx));
      return (0-resp);
   }

   free(timestamp);
   free(e_timestamp);
   free(qs);
   free(sigin);
   free(sig);
   free(e_sig);

   int num_messages = (-1);
   int num_invisible = (-1);

   char *s = strstr(txt, "<Name>ApproximateNumberOfMessages</Name>");
   if (s) {
      char *t = strstr(s, "<Value>");
      if (t) {
         t += 7;
         num_messages = 0;
         while (isdigit(*t)) num_messages = num_messages*10 + (*t-'0'), t++;
      }
   }
   s = strstr(txt, "<Name>ApproximateNumberOfMessagesNotVisible</Name>");
   if (s) {
      char *t = strstr(s, "<Value>");
      if (t) {
         t += 7;
         num_invisible = 0;
         while (isdigit(*t)) num_invisible = num_invisible*10 + (*t-'0'), t++;
      }
   }
   iam_free(txt);
   // syslog(LOG_DEBUG, "sqs visible=%d, invisible=%d\n", num_messages,  num_invisible);
   return (num_messages);
}

/* get message
 */

// get messages from response

static char *decodeText(char *in, char *end) {
   char *ret = (char*) malloc(end-in+2);
   char *out = ret;
   while (*in && in<end) {
      if (!strncmp(in, "&quot;", 6)) *out++='"',in+=6;
      else *out++ = *in++;
   }
   *out = '\0';
   return ret;
}

SQSMessage *sqs_getMessages(RestContext *ctx, int max_messages) {
   SQSMessage *ret = NULL;
   SQSMessage *retl = NULL;

   if (max_messages<1) return NULL;
   char *timestamp = iam_timestampNow();
   char *e_timestamp = iam_urlencode(timestamp);
   int bufl = 1024;
   char *qs = (char*) malloc(bufl);
   snprintf(qs, bufl,
      "AWSAccessKeyId=%s&Action=%s&AttributeName.1=All&MaxNumberOfMessages=%d&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=%s",
      awsKeyId, sqsRecvAction, max_messages, e_timestamp);
   char *sigin = (char*) malloc(bufl);
   snprintf(sigin, bufl, "GET\n%s\n%s\n%s", sqsHost, sqsPath, qs);
   char *sig = iam_computeAWSSignature256(awsKey, sigin);
   char *e_sig = iam_urlencode(sig);
   snprintf(sigin, bufl, "%s?%s&Signature=%s", sqsUrl, qs, e_sig);
   
   TRACE(stderr, "sqs recv qs = %s\n", sigin);
   char *txt = iam_getPage(ctx, sigin);

   if (!txt) {
      long resp = iam_restContextResp(ctx);
      return (errSQSMessage(resp, iam_restContextError(ctx)));
   }
   free(timestamp);
   free(e_timestamp);
   free(qs);
   free(sigin);
   free(sig);
   free(e_sig);

   // decode the text messages: list on <message>
   // simple minded xml parsing
   char *msgp = txt;
   char *msge = txt;

   TRACE(stderr, "recv = [%s]\n", txt);
   
   while (msge!=NULL  && (msgp=strstr(msge, "<Message>"))) {
      msge = strstr(msgp, "</Message>");
      if (!msge) break;  // required

      char *msg_json = NULL;
      char *msg_handle = NULL;
      char *s = strstr(msgp, "<Body>");
      if (!s) break;
      char *t = strstr(s, "</Body>");
      if (!t) break;

      msg_json = decodeText(s+6, t);
      s = strstr(msgp, "<ReceiptHandle>");
      if (s) {
         char *t = strstr(s, "</ReceiptHandle>");
         if (t) msg_handle = decodeText(s+15, t);
      }
      if (msg_json && msg_handle) {
         SQSMessage *sqsm = newSQSMessage(msg_json, msg_handle);
         if (sqsm) {   // link at end
            if (retl) {
               retl->next = sqsm;
            } else {
               ret = sqsm;
            }
            retl = sqsm;
         }
      }
      iam_free(msg_json);
      iam_free(msg_handle);
   }

   iam_free(txt);
   return (ret);
}

SQSMessage *sqs_getMessage(RestContext *ctx) {
   return (sqs_getMessages(ctx, 1));
}


/* delete a message
 */

int sqs_deleteMessage(RestContext *ctx, char *handle) {
   char *timestamp = iam_timestampNow();
   char *e_timestamp = iam_urlencode(timestamp);
   int bufl = 1024;
   char *qs = (char*) malloc(bufl);
   char *e_handle = iam_urlencode(handle);
   snprintf(qs, bufl,
      "AWSAccessKeyId=%s&Action=%s&ReceiptHandle=%s&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=%s",
      awsKeyId, sqsDeleteAction, e_handle, e_timestamp);
   char *sigin = (char*) malloc(bufl);
   snprintf(sigin, bufl, "GET\n%s\n%s\n%s", sqsHost, sqsPath, qs);
   char *sig = iam_computeAWSSignature256(awsKey, sigin);
   char *e_sig = iam_urlencode(sig);
   snprintf(sigin, bufl, "%s?%s&Signature=%s", sqsUrl, qs, e_sig);
   
   char *txt = iam_getPage(ctx, sigin);
   long resp = 0;
   if (!txt) {
      resp = iam_restContextResp(ctx);
      syslog(LOG_ERR, "aws getmsg failed: %s", iam_restContextError(ctx));
      return (resp);
   }
   free(timestamp);
   free(e_timestamp);
   free(e_handle);
   free(qs);
   free(sigin);
   free(sig);
   free(e_sig);
   iam_free(txt);
   if (resp>=300) return (-2);
   return (0);

}



/* Send a message to sqs:
   - base64 encode the message
   - add json wrappers ( similar to what sns adds )
   - generate signature
   - send to SQS
   - returns aws http status
 */

// simple uuid generator
#include <uuid/uuid.h>
char *_uuidgen() {
   char *ustr = (char*) malloc(40);
   uuid_t u;
   uuid_generate(u);
   uuid_unparse(u, ustr);
   return (ustr);
}

// default queue 
int sqs_sendMessage(RestContext *ctx, char *sub, char *msg, int msgl) {
   return sqs_sendMessageQueue(ctx, sub, msg, msgl, sqsUrl);
}

// user specified url and queue
int sqs_sendMessageQueue(RestContext *ctx, char *sub, char *msg, int msgl, char *queueUrl) {

   char *host = strdup(queueUrl+8);
   char *s = strchr(host, '/');
   char *path = strdup(s);
   *s = '\0';
   char *e_url = iam_urlencode(queueUrl);
   TRACE(stderr, "host=%s, path=%s\n", host, path);
   TRACE(stderr, "encurl=%s\n", e_url);

   char *b64msg = iam_dataToBase64(msg, msgl);
   char *e_b64msg = iam_urlencode(b64msg);
   char *timestamp = iam_timestampNow();
   char *e_timestamp = iam_urlencode(timestamp);

   // wrap
   cJSON *jdoc = cJSON_CreateObject();
   cJSON_AddItemToObject(jdoc, "Type", cJSON_CreateString("UWEvent"));
   char *mid = _uuidgen(); 
   cJSON_AddItemToObject(jdoc, "MessageId", cJSON_CreateString(mid));
   free(mid);
   cJSON_AddItemToObject(jdoc, "Subject", cJSON_CreateString(sub));
   cJSON_AddItemToObject(jdoc, "Timestamp", cJSON_CreateString(timestamp));
   cJSON_AddItemToObject(jdoc, "Message", cJSON_CreateString(e_b64msg));
   char *wrapped = cJSON_PrintUnformatted(jdoc);
   char *e_wrapped = iam_urlencode(wrapped);
   cJSON_Delete(jdoc);

   int bufl = strlen(e_wrapped)+1024;
   TRACE(stderr, "bufl=%d, b64msg=%zu, e_b64msg=%zu, e_timestamp=%zu\n",
        bufl, strlen(b64msg), strlen(e_b64msg), strlen(e_timestamp) );
   char *qs = (char*) malloc(bufl);
   char *qspost = (char*) malloc(bufl);
   snprintf(qs, bufl,
      "AWSAccessKeyId=%s&Action=SendMessage&MessageBody=%s&MessageGroupId=control&QueueUrl=%s&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=%s",
      awsKeyId, e_wrapped, e_url, e_timestamp);
   // free(wrapped);
   free(e_wrapped);
   TRACE(stderr, "qs=%s\n", qs);
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
   TRACE(stderr, "rsp = %s\n", rsp);
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
   free(timestamp);
   free(e_timestamp);
   free(qs);
   free(sigin);
   free(sig);
   free(e_sig);
   free(qspost);
   free(e_url);
   return (ctx->http_resp);
}


int sqs_init(char *url, char *key, char *keyId) {

   iam_crypt_init();
   sqsUrl = url;
   sqsHost = strdup(sqsUrl+8);
   char *s = strchr(sqsHost, '/');
   sqsPath = strdup(s);
   *s = '\0';
   awsKeyId = keyId;
   awsKey = key;

   return (1);
}  
