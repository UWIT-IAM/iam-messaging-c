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

#ifndef _iam_crypt_h
#define _iam_crypt_h
char *iam_dataToBase64(char *txt, int txtl);
int iam_base64ToData(char *txt64, int txt64l, char **data, int *datal);
char *iam_base64ToText(char *text64);
char *iam_timestampNow();
char *iam_urlencode (char *txt);

int iam_setPubKey(char *id, char *url);
int iam_setPvtKey(char *id, char *url);
char *iam_getSignUrl(char *id);


char *iam_computeAWSSignature256(char *key, char *str);
char *iam_computeAzureSignature256(char *key, char *str);
char *iam_computeSignature(char *str, char *sigid);
char *iam_genHmac(unsigned char *data, int dl, char *keyname);
int iam_verifySignature(char *str, char *sigb64, char *sigurl);
int iam_verifySignature_2(char *str, char *sigb64, char *sigurl);

int iam_encryptText(char *keyname, char *in, int inlen, char **out, char **iv);
int iam_decryptText(char *keyname, char *encb64, char **out, char *iv);
int iam_decryptText_2(char *keyname, char *encb64, char **out, char *iv);
int iam_addCryptkey(char *name, char *keyb64);

int iam_crypt_init();
void iam_crypt_cleanup();
char *iam_uuid();
char *iam_getFile (char *file);

#include "cJSON.h"
#include <curl/curl.h>

char *safeGetString(cJSON *item, char *label);
char *safeDupString(cJSON *item, char *label);
double safeGetDouble(cJSON *item, char *label);


char *iam_strdup(char *str);
void iam_free(void *mem);

extern int iamVerbose;
extern int iamSyslog;

/* REST access */
typedef struct MemBuf_ {
   char *mem;
   int len;
   int pos;
} MemBuf;
size_t iam_page_reader(void *buf, size_t len, size_t num, void *wp);
MemBuf *newMemBuf();

typedef struct RestContext_ {
   CURL *curl;
   MemBuf *mem;
   char *error;
   long http_resp;
} RestContext;
RestContext *iam_restContext();
void iam_freeRestContext(RestContext *ctx);
#define iam_restContextResp(ctx) (ctx->http_resp)
#define iam_restContextError(ctx) (ctx->error)

char *iam_getPage(RestContext *ctx, char *url);

#endif
