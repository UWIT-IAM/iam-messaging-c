/* ========================================================================
 * Copyright (c) 2012-2103 The University of Washington
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

/* Crypto for the messaging tools */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <curl/curl.h>
// #include <curl/types.h>
#include <curl/easy.h>

#include "iam_crypt.h"
int iamVerbose = 0;
int iamSyslog = 0;


char *iam_strdup(char *s) {
   if (s) return strdup(s);
   return NULL;
}
void iam_free(void *mem) {
   if (mem) free (mem);
}

/* get file to string */
char *iam_getFile(char *name) {
   FILE *f = fopen(name, "rb");
   if (!f) {
      syslog(LOG_ERR, "open of file %s failed: %m", name);
      return (NULL);
   }
   fseek(f, 0L, SEEK_END);
   long l = ftell(f);
   char *fb = (char*) malloc(l+1);
   rewind(f);
   if (fread(fb, l, 1, f)!=1) {
      syslog(LOG_ERR, "read of file %s failed: %m", name);
      fclose(f);
      free(fb);
      return (NULL);
   }
   fb[l] = '\0';
   fclose(f);
   return (fb);
}


/* --------- data conversion ----------------*/

/* convert data to base64 - returns malloc'd string */

char *iam_dataToBase64(char *txt, int txtl) {
   BIO *bmem, *b64;
   BUF_MEM *bmp;
   char *ret;

   b64 = BIO_new(BIO_f_base64());
   BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
   bmem = BIO_new(BIO_s_mem());
   b64 = BIO_push(b64, bmem);
   BIO_write(b64, txt, txtl);
   BIO_flush(b64);
   BIO_get_mem_ptr(b64, &bmp);
   ret = (char *)malloc(bmp->length * 2);
   memcpy(ret, bmp->data, bmp->length);
   ret[bmp->length] = 0; 
   BIO_free_all(b64);
   return ret;
}

/* convert base64 encoded text to data */

int iam_base64ToData(char *txt64, int txt64l, char **data, int *datal) {
   char *buf;
   int nb;
   BIO *b64, *bmem;

   b64 = BIO_new(BIO_f_base64());
   BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
   bmem = BIO_new_mem_buf(txt64, txt64l);
   BIO_push(b64, bmem);
   buf = malloc(txt64l);
   nb = BIO_read(b64, buf, txt64l);
   BIO_flush(b64);
   *data = buf;
   if (datal!=NULL) *datal = nb;
   BIO_free_all(b64);
   return (1);
}

// convert b64 text to string.  returns malloc'd string
char *iam_base64ToText(char *txt64) {
   char *buf;
   int bufl;
   int txt64l = strlen(txt64);
   iam_base64ToData(txt64, txt64l, &buf, &bufl);
   buf[bufl] = '\0';
   return (buf);
}

// generate a timestamp  - returns malloc'd string

char *iam_timestampNow() {
   char *ret = (char*) malloc(64);
   struct timeval tv;
   time_t t = time(NULL);
   struct tm sgm;
   struct tm *gm = &sgm;
   gmtime_r(&t, &sgm);
   gettimeofday(&tv, NULL);
   int msec = tv.tv_usec/1000;
   snprintf(ret, 64, "%4d-%02d-%02dT%02d:%02d:%02d.%03dZ",
     gm->tm_year+1900, gm->tm_mon+1, gm->tm_mday, gm->tm_hour, gm->tm_min, gm->tm_sec, msec);
   return (ret);
}

// url encoding.  returns malloc'd string
char rfc3986[256];
char *iam_urlencode(char *txt) {
   char *enc = (char*) malloc(strlen(txt)*3 + 1);
   unsigned char c;
   int ci = 0;
   while ((c=*txt)!=0) {
      if (rfc3986[c]) {
         enc[ci++] = c;
      } else {
         snprintf(&enc[ci], 4, "%%%02X", c);
         ci += 3;
      }
      txt++;
   }
   enc[ci] = 0;
   return (enc);
}


char *_iam_urlencode (char *txt) {
  int i;
  char *fixchar = " \n$&+,/:;=?@! ";
  char *hexchar = "0123456789ABCDEF20";
  
  int s = 0;
  for (i=0; txt[i]; i++,s++) if (strchr(fixchar, txt[i])) s += 4;
  char *enc = (char*) malloc(s+4);
  memset(enc, '\0', s+4);

  for (i=0,s=0; txt[i]; i++) {
     if (strchr(fixchar, txt[i])) {
        unsigned char c = txt[i];
        enc[s++] = '%';
        enc[s++] = hexchar[(c>>4) & 0xF];
        enc[s++] = hexchar[c & 0xF];
      }
      else enc[s++] = txt[i];
   }
   return (enc);
}

/* ---------- web page handler ---------------- */

size_t iam_page_reader(void *buf, size_t len, size_t num, void *wp)
{
  size_t realsize = len*num;
  if (wp) {
     MemBuf *mb = (MemBuf*) wp;
     if (mb->len<mb->pos+realsize+1) {
        mb->len += realsize + 1;
        mb->mem = realloc(mb->mem, mb->len);
     }
     memcpy(&(mb->mem[mb->pos]), buf, realsize);
     mb->pos += realsize;
     mb->mem[mb->pos] = '\0';
  }
  return (realsize);
}

MemBuf *newMemBuf() {
   MemBuf *membuf = (MemBuf*) malloc(sizeof(MemBuf));
   membuf->mem = (char*) malloc(1024);
   memset(membuf->mem, 0, 1024);
   membuf->len = 1024;
   membuf->pos = 0;
   membuf->mem[0] = '\0';
   return membuf;
}

RestContext *iam_restContext() {
   RestContext *ctx = (RestContext*) malloc(sizeof(RestContext));
   memset(ctx, 0, sizeof(RestContext));
   ctx->mem = newMemBuf();
   ctx->error = (char*) malloc(CURL_ERROR_SIZE);
   memset(ctx->error, 0, CURL_ERROR_SIZE);
   CURL *curl = curl_easy_init();
   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, iam_page_reader);
   curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
   curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0L);
   curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
   curl_easy_setopt(curl, CURLOPT_TIMEOUT, 40);
   curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
   curl_easy_setopt(curl, CURLOPT_UPLOAD, 0L);
   curl_easy_setopt(curl, CURLOPT_POST, 0L );
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx->mem);
   curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, ctx->error);
   ctx->curl = curl;
   return (ctx);
}

void iam_freeRestContext(RestContext *ctx) {
   curl_easy_cleanup(ctx->curl);
   free(ctx->mem->mem);
   free(ctx->mem);
   free(ctx->error);
   free(ctx);
}


// initialize a curl struct

/**
int cleanupCurlContext() {
   curl_easy_cleanup(curl);
   curl = NULL;
   free(curl_membuf->mem);
   free(curl_membuf);
   curl_membuf = NULL;
}
**/


// get one page

char *iam_getPage(RestContext *ctx, char *url) {

   curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
   curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, NULL );
   curl_easy_setopt(ctx->curl, CURLOPT_POST, 0L );

   CURLcode status = curl_easy_perform(ctx->curl);
   if (status!=CURLE_OK) {
      // syslog(LOG_ERR, "aws getmsg failed: %s", curlerror);
      // retry one time
      return (NULL);
   }

   curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &ctx->http_resp);
   if (ctx->http_resp>=300) {
      syslog(LOG_ERR, "get of %s failed: %ld", url, ctx->http_resp);
      // cleanupCurlContext();
      return (NULL);
   }
   char *rsp = strdup(ctx->mem->mem);
   ctx->mem->pos = 0;
   return (rsp);
}


/* -----------  signature processing  ----------------- */

/* certificate  key storage for signatures */
typedef struct CertPKey_ {
   struct CertPKey_ *next;
   char *id;          // local reference
   char *url;         // pub: url of cert pem;   pvt: filename of cert key pem
   EVP_PKEY *pkey;    // pub: pub key of cert;   pvt: pvt key from file
} CertPKey;

CertPKey *pubKeys = NULL;
CertPKey *pvtKeys = NULL;

// add a pub key from a cert pem
static CertPKey *newPubKey(char *id, char *pem, char *url) {
  
   BIO *kbio = BIO_new_mem_buf(pem, strlen(pem));
   EVP_PKEY *pkey=NULL;
   X509 *crt = PEM_read_bio_X509(kbio, NULL, NULL, NULL);
   pkey = X509_get_pubkey(crt);
   BIO_free(kbio);
   X509_free(crt);
   free(pem);

   CertPKey *pk = (CertPKey*) malloc(sizeof(CertPKey));
   pk->id = iam_strdup(id);
   pk->url = iam_strdup(url);
   pk->pkey = pkey;
   pk->next = pubKeys;
   pubKeys = pk;
   if (iamVerbose) syslog(LOG_DEBUG, "generated new pk at %s", pk->url);
   return (pk);
}

// find cached cert or download
static CertPKey *findPubKey(char *id, char *url) {
   CertPKey *key;
   for (key=pubKeys; key; key=key->next) {
      if (id && !strcmp(key->id, id)) return (key);
      if (url && !strcmp(key->url, url)) return (key);
   }
   if (!url) return (0);

   if (iamVerbose) syslog(LOG_DEBUG, "retrieving cert from: %s", url);
   RestContext *h = iam_restContext();
   char *pem = iam_getPage(h, url);
   iam_freeRestContext(h);
   if (pem) return (newPubKey(id, pem, url));
   syslog(LOG_ERR, "could not get singing cert from: %s", url);
   return (NULL);
}

// external vers of above
int iam_setPubKey(char *id, char *url) {
   if (findPubKey(id, url)) {
      return (1);
   }
   return (0);
}
char *iam_getSignUrl(char *id) {
   CertPKey *k = findPubKey(id, NULL);
   if (k) return (k->url);
   return NULL;
} 


// add a pvt key from a file (url)
static CertPKey *newPvtKey(char *id, char *url) {
  
   FILE *fp = fopen(url, "r");
   if (!fp) {
      return NULL;
   }
   EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
   fclose(fp);

   CertPKey *pk = (CertPKey*) malloc(sizeof(CertPKey));
   pk->id = iam_strdup(id);
   pk->url = iam_strdup(url);
   pk->pkey = pkey;
   pk->next = pvtKeys;
   pvtKeys = pk;
   if (iamVerbose) syslog(LOG_DEBUG, "generated new pvt key at %s", pk->url);
   return (pk);
}

// find cached pvt key or read from file
static CertPKey *findPvtKey(char *id, char *url) {
   CertPKey *key;
   for (key=pvtKeys; key; key=key->next) {
      if (id && !strcmp(key->id, id)) return (key);
      if (url && !strcmp(key->url, url)) return (key);
   }
   if (!url) return (NULL);
   if (iamVerbose) syslog(LOG_DEBUG, "retrieving key from: %s", url);
   return (newPvtKey(id, url));
}

// public version of above
int iam_setPvtKey(char *id, char *url) {
   if (findPvtKey(id, url)) return (1);
   return (0);
}
 
/* compute an aws signature - sha256 - returns malloc'd string  */

char *iam_computeAWSSignature256(char *key, char *str) {
   HMAC_CTX ctx;
   char sig[256];
   int sigl;

   HMAC_CTX_init(&ctx);
   HMAC_Init(&ctx, key, strlen(key), EVP_sha256());
   HMAC_Update(&ctx,(unsigned char*)str, strlen(str));
   HMAC_Final(&ctx,(unsigned char*)sig,(unsigned int*)&sigl);
   HMAC_CTX_cleanup(&ctx);
   return iam_dataToBase64(sig, sigl);
}

/* compute an azure signature - sha256 - returns malloc'd string  */

char *iam_computeAzureSignature256(char *key, char *str) {
   HMAC_CTX ctx;
   char sig[256];
   int sigl;
   
   char *rkey;
   int rkeylen;
   iam_base64ToData(key, strlen(key), &rkey, &rkeylen);

   HMAC_CTX_init(&ctx);
   HMAC_Init(&ctx, key, strlen(key), EVP_sha256());
   HMAC_Update(&ctx,(unsigned char*)str, strlen(str));
   HMAC_Final(&ctx,(unsigned char*)sig,(unsigned int*)&sigl);
   HMAC_CTX_cleanup(&ctx);
   char *ret = iam_dataToBase64(sig, sigl);
   return ret;
}


/* create a signature.  locate cert by id   - returns malloc'd string */

char *iam_computeSignature(char *str, char *sigid) {
   EVP_MD_CTX *mctx;
   char sig[256];
   size_t sigl = 256;
   int ok = 1;

   if ((mctx = EVP_MD_CTX_create())==NULL) {
      return NULL;
   }

   // fint the private key
   CertPKey *pk = findPvtKey(sigid, NULL);
   if (!pk) {
      syslog(LOG_ERR, "can't find key for %s", sigid);
      ok = 0;
   }
   if (ok && EVP_DigestSignInit(mctx, NULL, EVP_sha1(), NULL, pk->pkey)!=1) {
      ok = 0;
   }
   if (ok && EVP_DigestSignUpdate(mctx, str, strlen(str))!=1) {
      ok = 0;
   }
   if (ok && EVP_DigestSignFinal(mctx, (unsigned char*)sig, &sigl)!=1) {
      ok = 0;
   }
   
   EVP_MD_CTX_destroy(mctx);
   if (!ok) return NULL;
   return iam_dataToBase64(sig, sigl);
}


/* verify a signature.  localte cert by url */

int iam_verifySignature(char *str, char *sigb64, char *sigurl) {
   EVP_MD_CTX *mctx;
   char *sig;
   int sigl;

   if ((mctx = EVP_MD_CTX_create())==NULL) {
      syslog(LOG_ERR, "can't create context");
      return 0;
   }

   CertPKey *pk = findPubKey(NULL, sigurl);
   if (!pk) {
      EVP_MD_CTX_destroy(mctx);
      syslog(LOG_ERR, "can't find cert at %s", sigurl);
      return (0);
   }

   iam_base64ToData(sigb64, strlen(sigb64), &sig, &sigl);

   int r = EVP_VerifyInit(mctx, EVP_sha1());
   r = EVP_VerifyUpdate(mctx, (void*) str, strlen(str));
   r = EVP_VerifyFinal(mctx, (unsigned char*) sig, sigl, pk->pkey);

   EVP_MD_CTX_destroy(mctx);
   free(sig);
   return (r);
}

/* Display some data in hex. Note no line breaking.
   Note the arbitrary upper limit on length.
   The returned buffer must be freed.
   (this for debug) */

#ifdef NEEDBYTESTOHEX
static char hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
static char *bytesToHex(unsigned char *byt, int n)
{
   int i;
   char *buf, *p;
   buf = (char *) malloc(n*4+16);
   p = buf;
   for (i=0;i<n;i++) {
      unsigned int b = *byt++;
      *p++ = hexchars[b/16];
      *p++ = hexchars[b-(b/16)*16];
   }
   *p = '\0';
   return (buf);
}
#endif

/* simple cryption */

const EVP_CIPHER *crypt_cipher;
const EVP_MD *crypt_hash;


/* crypt key storage */
typedef struct Cryptkey_ {
   struct Cryptkey_ *next;
   char *id;
   char *key;
   int keylen;
   const EVP_CIPHER *cipher;
   const EVP_MD *hash;
} Cryptkey;

Cryptkey *cryptkeys = NULL;
// add a key from a b64 string

static Cryptkey *newCryptkey(char *id, const EVP_CIPHER *cc, const EVP_MD *h, char *keyb64) {

   Cryptkey *ck = (Cryptkey*) malloc(sizeof(Cryptkey));
   ck->id = iam_strdup(id);
   iam_base64ToData(keyb64, strlen(keyb64), &(ck->key), &(ck->keylen));
   ck->cipher = cc;
   ck->hash = h;
   ck->next = cryptkeys;
   cryptkeys = ck;
   return (ck);
}

static Cryptkey *findCryptkey(char *id) {
   Cryptkey *key;
   for (key=cryptkeys; key; key=key->next) {
      if (!strcmp(key->id, id)) return (key);
   }
   return (NULL);
}

int iam_addCryptkey(char *id, char *keyb64) {
   newCryptkey(id, crypt_cipher, crypt_hash, keyb64);
   return (1);
}


/* Generate a MAC  - returns malloc'd string */
char *iam_genHmac(unsigned char *data, int dl, char *keyname)
{
   Cryptkey *ck = findCryptkey(keyname);
   char *h = (char*)malloc(EVP_MAX_MD_SIZE);
   unsigned int hl = 0;
   char *ret;

   memset (h, 0, EVP_MAX_MD_SIZE);
   HMAC(crypt_hash, (void*) ck->key, ck->keylen, data, dl, (unsigned char*)h, &hl);
   ret = iam_dataToBase64(h, hl);
   return (ret);
}

/* encrypt or decrypt */
int iam_crypt(Cryptkey *ck, int mode, char *out, int *outlen, char *in, int inlen, char *iv)
{
   int ol;
   int len;
   int s;

   EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
   EVP_CipherInit(ctx, ck->cipher, (unsigned char*)ck->key, (unsigned char*)iv, mode);
   s = EVP_CipherUpdate(ctx, (unsigned char*)out, &ol, (unsigned char*)in, inlen);
   *outlen = ol;
   out += *outlen;

   if (s) s = EVP_CipherFinal(ctx, (unsigned char*)out, &ol);
   *outlen += ol;
   len = *outlen;
   EVP_CIPHER_CTX_cleanup(ctx);
   free(ctx);
   if (s) return (len);
   return (0);
}

// returns a malloc'd string (base64 of the encrypted data) and the IV (also b64)
int iam_encryptText(char *keyname, char *in, int inlen, char **out64, char **iv64) {
   
   Cryptkey *ck = findCryptkey(keyname);

   int ivl = EVP_CIPHER_iv_length(ck->cipher);
   char iv[EVP_MAX_IV_LENGTH];
   RAND_bytes((unsigned char*)iv, ivl);
   if (iv64!=NULL) {
      *iv64 = iam_dataToBase64(iv, ivl);
   }
   
   int blklen = EVP_CIPHER_block_size(ck->cipher);
   char *enctxt = (char*)malloc(inlen + blklen);
   int enclen;
   int r = iam_crypt(ck, 1, enctxt, &enclen, in, inlen, iv);

   // ascii'ify
   *out64 = iam_dataToBase64(enctxt, enclen);

   free(enctxt);
   return (r);
}

int iam_decryptText(char *keyname, char *encb64, char **out, char *iv64) {

   char *enctxt;
   int enctxtl;
   char *iv;

   iam_base64ToData(iv64, strlen(iv64), &iv, NULL);
   iam_base64ToData(encb64, strlen(encb64), (char**) &enctxt, &enctxtl);

   Cryptkey *ck = findCryptkey(keyname);
   if (!ck) return (0);

   int blklen = EVP_CIPHER_block_size(crypt_cipher);
   char *xmsg = (char*) malloc(enctxtl+blklen);
   int xmsglen;
   int r = iam_crypt(ck, 0, xmsg, &xmsglen, enctxt, enctxtl, iv);
   xmsg[xmsglen] = '\0';
   *out = xmsg;
   free(iv);
   free(enctxt);

   return (r);
   
}

/* --- openssl thread needs ---- */
static pthread_mutex_t *lock_cs;
static long *lock_count;

static void locking_callback(int mode, int type, char *file, int line) {
   if (mode & CRYPTO_LOCK) {
      pthread_mutex_lock(&(lock_cs[type]));
      lock_count[type]++;
   } else {
      pthread_mutex_unlock(&(lock_cs[type]));
   }
}

static unsigned long thread_id(void) {
   unsigned long ret;
   ret=(unsigned long)pthread_self();
   return(ret);
}


static void thread_setup(void) {
   int i;

   lock_cs=OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
   lock_count=OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
   for (i=0; i<CRYPTO_num_locks(); i++) {
      lock_count[i]=0;
      pthread_mutex_init(&(lock_cs[i]),NULL);
   }

   CRYPTO_set_id_callback((unsigned long (*)())thread_id);
   CRYPTO_set_locking_callback((void (*)())locking_callback);
}

static void thread_cleanup(void) {
   int i;

   CRYPTO_set_locking_callback(NULL);
   fprintf(stderr,"cleanup\n");
   for (i=0; i<CRYPTO_num_locks(); i++) {
       pthread_mutex_destroy(&(lock_cs[i]));
       fprintf(stderr,"%8ld:%s\n",lock_count[i], CRYPTO_get_lock_name(i));
   }
   OPENSSL_free(lock_cs);
   OPENSSL_free(lock_count);
}



/* ----- Initialize ---- */

int iam_crypt_init() {
   static int inited = 0;
   if (inited) return(1);

   // init openssl
   OpenSSL_add_all_algorithms();
   SSL_load_error_strings();
   SSL_library_init();

   thread_setup();

   crypt_cipher = EVP_aes_128_cbc();
   crypt_hash = EVP_sha1();

   curl_global_init(CURL_GLOBAL_ALL);

   int i;
   for (i=0;i<256;i++) rfc3986[i] = isalnum(i) || i == '~' || i == '-' || i == '.' || i == '_' ? i : 0;

   inited = 1;
   return (1);
}

void iam_crypt_cleanup() {
   thread_cleanup();
}


/* Gen a UUID - returns malloc'd string  */

static FILE *randfile = NULL;
char *iam_uuid() {
  char *uu = (char*) malloc(48);
  unsigned char rb[16];
  int i,j;

  if (!randfile) randfile = fopen("/dev/urandom","r");
  if (!randfile) {
     perror("/dev/urandom");
     return (NULL);
  }

  fread(rb, 16, 1, randfile); /* get 128 bits */
  for (i=0,j=0;i<16;i++) {
    if (i==4||i==6||i==8||i==10) uu[j]='-',j++;
    sprintf(&uu[j], "%02x", rb[i]);
    j+=2;
  }
  uu[37] = '\0';
  return uu;
}

/* cJSON tools */

#include "cJSON.h"
// get a string from a JSON element
char *safeGetString(cJSON *item, char *label) {
   char *ret = NULL;
   cJSON *i = cJSON_GetObjectItem(item, label);
   if (i) ret = i->valuestring;
   return (ret);
}

// dup a string from a JSON element
char *safeDupString(cJSON *item, char *label) {
   char *ret = safeGetString(item, label);
   if (ret) return (strdup(ret));
   return (NULL);
}

// get a double from a JSON element
double safeGetDouble(cJSON *item, char *label) {
   double ret = NAN;
   cJSON *i = cJSON_GetObjectItem(item, label);
   if (i) ret = i->valuedouble;
   return (ret);
}

