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

#ifndef sns_h
#define sns_h

typedef struct SNSMessage_ {
   char *contentType;
   char *messageId;
   char *messageContext;
   char *type;
   char *subject;
   char *timestamp;
   char *topicArn;
   char *message;
   int   verified;
} SNSMessage;

#include "iam_crypt.h"

int sns_init();
int sns_sendMessage(RestContext *ctx, char *sub, char *msg, int msgl);
int sns_sendMessageArn(RestContext *ctx, char *sub, char *msg, int msgl, char *host, char *e_arn);
int sns_processSnsMessage(char *snsmsg, int(*msg_handler)(SNSMessage*));
char *sns_lastMessage();


#endif
