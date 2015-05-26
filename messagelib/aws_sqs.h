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

#ifndef sqs_h
#define sqs_h

#include "iam_crypt.h"
typedef struct SQSMessage_ {
   struct SQSMessage_ *next;
   char *messageId;
   char *type;
   char *subject;
   char *timestamp;
   char *topicArn;
   char *message;
   char *handle;
   int   verified;
} SQSMessage;

int sqs_init();
SQSMessage *sqs_getMessage(RestContext *ctx);
SQSMessage *sqs_getMessages(RestContext *ctx, int max);
int sqs_getNumMessages(RestContext *ctx);
int sqs_getInfo();
void freeSQSMessage(SQSMessage *sqs);
int sqs_deleteMessage(RestContext *ctx, char *handle);

#endif
