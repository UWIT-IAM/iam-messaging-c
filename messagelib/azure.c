/* ========================================================================
 * Copyright (c) 2015 The University of Washington
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

/* Azure tools */

#include <stdio.h>
#include <stdlib.h>
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
#include "iam_msg.h"
#include "azure.h"

#define TRACE if(0)fprintf


/* defaults, set by init */

char *access_key_name = NULL;
char *access_key_value = NULL;
char *def_namespace = NULL;
char *def_topic = NULL;
char *def_subscription = NULL;

/* single curl object used by all methods.
   membuf is where content is stored
   az_brprops get the BrokerProperties header text
 */

static CURL *az_curl = NULL;
MemBuf *az_membuf = NULL;
char *az_brprops = NULL;

size_t az_header_reader(void *buf, size_t len, size_t num, void *wp) {
  size_t realsize = len*num;
  char **bp = (char**)wp;
  if (!strncmp(buf, "BrokerProperties:", 17)) {
     printf ("is bp\n");
     *bp = strdup(buf);
  }
  return (realsize);
} 

CURL *az_getCurlHandle() {
   az_membuf = newMemBuf();
   char curlerror[CURL_ERROR_SIZE];
   
   CURL *curl = curl_easy_init();
   curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
   curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0L);
   curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
   curl_easy_setopt(curl, CURLOPT_TIMEOUT, 40); 
   curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, iam_page_reader);
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, az_membuf);
   curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, az_header_reader);
   curl_easy_setopt(curl, CURLOPT_HEADERDATA, &az_brprops);
   
   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
   
   curl_easy_setopt(curl, CURLOPT_UPLOAD, 0L);
   curl_easy_setopt(curl, CURLOPT_POST, 1L );
   curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlerror);
   return (curl);
}

/* Send to topic.
   The message is base64 encoded.
   Authentication and other headers added.
 */
   
int azure_sendMessage(char *sub, char *msg, int msgl, char *namespace, char *topic) {
   if (!az_curl) az_curl = az_getCurlHandle();
   if (namespace==NULL) namespace = def_namespace;
   if (topic==NULL) topic = def_topic;

   char *b64msg = iam_dataToBase64(msg, msgl);
   char *e_sub = iam_urlencode(sub);
   time_t timestamp = time(NULL);
   char *url = (char*) malloc(4096);
   sprintf(url, "https://%s.servicebus.windows.net:443/%s/messages", namespace, topic);
   char *e_url = iam_urlencode(url);
   // printf("e_url = [%s]\n", e_url);

   struct curl_slist *headers=NULL; 
   headers = curl_slist_append(headers, "Content-Type: application/atom+xml;type=entry;charset=utf-8");
   char hstr1[2048];
   sprintf(hstr1, "Content-Length: %jd", strlen(b64msg));
   headers = curl_slist_append(headers, hstr1);

   sprintf(hstr1, "%s\n%jd", e_url, timestamp);
   char *sig = iam_computeAWSSignature256(access_key_value, hstr1);
   char *e_sig = iam_urlencode(sig);
   // printf("e_sig = [%s]\n", e_sig);
   snprintf(hstr1, 2048, "Authorization: SharedAccessSignature sig=%s&se=%jd&skn=%s&sr=%s",
           e_sig, timestamp, access_key_name, e_url);
   // printf("e_sas = [%s]\n", hstr1);
   headers = curl_slist_append(headers, hstr1);

   MemBuf *pd = newMemBuf();
   curl_easy_setopt (az_curl, CURLOPT_URL, url);
   curl_easy_setopt(az_curl, CURLOPT_POST, 1L );
   curl_easy_setopt (az_curl, CURLOPT_POSTFIELDS, b64msg );
   curl_easy_setopt (az_curl, CURLOPT_POSTFIELDSIZE, strlen(b64msg));
   curl_easy_setopt(az_curl, CURLOPT_HTTPHEADER, headers); 

   CURLcode status = curl_easy_perform(az_curl);
   if (status!=CURLE_OK) {
      return (600);
   }

   long http_resp = 0;
   curl_easy_getinfo(az_curl, CURLINFO_RESPONSE_CODE, &http_resp);
   // curl_easy_cleanup(curl);
   TRACE(stderr, "curl resp = %ld\n", http_resp);
   free(b64msg);
   free(e_sub);
   free(sig);
   free(e_sig);
   free(pd);
   return (http_resp);
}


// receive
AzureMessage *azure_recvMessage(char *namespace, char *topic, char *subscription) {
   if (!az_curl) az_curl = az_getCurlHandle();
   if (namespace==NULL) namespace = def_namespace;
   if (topic==NULL) topic = def_topic;
   if (subscription==NULL) subscription = def_subscription;

   // int timeout = 60;
   time_t timestamp = time(NULL);

   char *url = (char*) malloc(4096);
   // sprintf(url, "https://%s.servicebus.windows.net:443/%s/subscriptions/%s/messages/head?timeout=2", namespace, topic, subscription);
   sprintf(url, "https://%s.servicebus.windows.net/%s/subscriptions/%s/messages/head?timeout=30", namespace, topic, subscription);
   printf ("url[%s]\n", url);
   char *e_url = iam_urlencode(url);
   // printf("e_url = [%s]\n", e_url);

   struct curl_slist *headers=NULL; 
   headers = curl_slist_append(headers, "Content-Type: application/atom+xml;type=entry;charset=utf-8");
   char hstr1[2048];
   sprintf(hstr1, "Content-Length: 0");
   headers = curl_slist_append(headers, hstr1);

   sprintf(hstr1, "%s\n%jd", e_url, timestamp);
   char *sig = iam_computeAWSSignature256(access_key_value, hstr1);
   char *e_sig = iam_urlencode(sig);
   // printf("e_sig = [%s]\n", e_sig);
   snprintf(hstr1, 2048, "Authorization: SharedAccessSignature sig=%s&se=%jd&skn=%s&sr=%s",
           e_sig, timestamp, access_key_name, e_url);
   // printf("e_sas = [%s]\n", hstr1);
   headers = curl_slist_append(headers, hstr1);

   curl_easy_setopt (az_curl, CURLOPT_URL, url);
   curl_easy_setopt(az_curl, CURLOPT_POST, 0L );
   curl_easy_setopt(az_curl, CURLOPT_UPLOAD, 0L);

    curl_easy_setopt(az_curl, CURLOPT_POST, 1L );
    char *buf = "";
    curl_easy_setopt (az_curl, CURLOPT_POSTFIELDS, buf );
    curl_easy_setopt (az_curl, CURLOPT_POSTFIELDSIZE, 0L);

   /* these to do a receive and delete operation 
   curl_easy_setopt(az_curl, CURLOPT_POST, 0L );
   curl_easy_setopt(az_curl, CURLOPT_CUSTOMREQUEST, "DELETE");
   */

   curl_easy_setopt(az_curl, CURLOPT_HTTPHEADER, headers); 
   curl_easy_setopt(az_curl, CURLOPT_HEADERFUNCTION, az_header_reader);
   curl_easy_setopt(az_curl, CURLOPT_HEADERDATA, &az_brprops);
#ifdef CURLOPT_TCP_KEEPIDLE
   curl_easy_setopt(az_curl, CURLOPT_TCP_KEEPIDLE , 3L);
#endif

   printf("call receiver\n");
   CURLcode status = curl_easy_perform(az_curl);
   if (status!=CURLE_OK) {
      return (NULL);
   }
   printf("call receiver back\n");
   long http_resp = 0;
   curl_easy_getinfo(az_curl, CURLINFO_RESPONSE_CODE, &http_resp);

   // curl_easy_cleanup(az_curl);
   // az_curl = NULL;

   if (http_resp==204) {
      // no messages
         free(sig);
         free(e_sig);
      return (NULL);
   }

   TRACE(stderr, "curl resp = %ld\n", http_resp);
   // printf("b64[%s]\n", az_member->mem);
   char *ret = iam_base64ToText(az_membuf->mem);
   if (ret==NULL || *ret=='\0') {
      // no messages
         printf("NULL message: resp=%ld\n", http_resp);
         free(sig);
         free(e_sig);
      return (NULL);
   }
   // printf("got[%s]\n", ret);
   // printf("getprop[%s]\n", az_brprops + 18);
   AzureMessage *msg = (AzureMessage*) malloc(sizeof(AzureMessage));
   cJSON *bp = cJSON_Parse(az_brprops + 18 );
   msg->msg = ret;
   msg->locktoken = safeGetString(bp, "LockToken");
   msg->seqno = safeGetString(bp, "SequenceNumber");
   msg->namespace = strdup(namespace);
   msg->subscription = strdup(subscription);
   msg->topic = strdup(topic);
   // printf("lock=%s\n", msg->locktoken);
   // printf("seqno=%s\n", msg->seqno);

   free(sig);
   free(e_sig);
   return (msg);
}


// receive
int azure_deleteMessage(AzureMessage *msg) {
   printf("--- delete ---\n");
   if (!az_curl) az_getCurlHandle();

   // int timeout = 60;
   time_t timestamp = time(NULL);

   char *url = (char*) malloc(4096);
   sprintf(url, "https://%s.servicebus.windows.net:443/%s/subscriptions/%s/messages/%s/%s",
       msg->namespace, msg->topic, msg->subscription, msg->seqno, msg->locktoken);
   char *e_url = iam_urlencode(url);
   // printf("e_url = [%s]\n", e_url);

   struct curl_slist *headers=NULL; 
   headers = curl_slist_append(headers, "Content-Type: application/atom+xml;type=entry;charset=utf-8");
   char hstr1[2048];
   sprintf(hstr1, "Content-Length: 0");
   headers = curl_slist_append(headers, hstr1);

   sprintf(hstr1, "%s\n%jd", e_url, timestamp);
   char *sig = iam_computeAWSSignature256(access_key_value, hstr1);
   char *e_sig = iam_urlencode(sig);
   // printf("e_sig = [%s]\n", e_sig);
   snprintf(hstr1, 2048, "Authorization: SharedAccessSignature sig=%s&se=%jd&skn=%s&sr=%s",
           e_sig, timestamp, access_key_name, e_url);
   // printf("e_sas = [%s]\n", hstr1);
   headers = curl_slist_append(headers, hstr1);

   curl_easy_setopt (az_curl, CURLOPT_URL, url);
   curl_easy_setopt(az_curl, CURLOPT_CUSTOMREQUEST, "DELETE"); 
   curl_easy_setopt(az_curl, CURLOPT_POST, 0L );
   curl_easy_setopt(az_curl, CURLOPT_UPLOAD, 0L);
   curl_easy_setopt(az_curl, CURLOPT_HTTPHEADER, headers); 
   curl_easy_setopt(az_curl, CURLOPT_HEADERFUNCTION, az_header_reader);
   curl_easy_setopt(az_curl, CURLOPT_HEADERDATA, &az_brprops);

   CURLcode status = curl_easy_perform(az_curl);
   if (status!=CURLE_OK) {
      return (0);
   }
   long http_resp = 0;
   curl_easy_getinfo(az_curl, CURLINFO_RESPONSE_CODE, &http_resp);
   // curl_easy_cleanup(curl);
   TRACE(stderr, "curl resp = %ld\n", http_resp);
   printf("--- deleted ---\n");

   free(sig);
   free(e_sig);
   return (1);
}


int azure_init(char *keyn, char *keyv, char *ns, char *topic, char *sub) {

   iam_crypt_init();

   access_key_name = iam_strdup(keyn);
   access_key_value = iam_strdup(keyv);
   def_namespace = iam_strdup(ns);
   def_topic = iam_strdup(topic);
   def_subscription = iam_strdup(sub);

   return (1);
}  
