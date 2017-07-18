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

#ifndef _iam_msg_h
#define _iam_msg_h

typedef struct IamMessage_ {
  char *contentType;
  char *version;
  char *uuid;
  char *messageContext;
  char *messageType;
  char *messageId;
  char *timestamp;
  char *sender;
  char *message;
  int error;
} IamMessage;

#define IAM_MSG_ERR_CRYPT -10
#define IAM_MSG_ERR_SIG -11
#define IAM_MSG_ERR_ENCODE -12

IamMessage *iam_newIamMessage();
void iam_freeIamMessage(IamMessage *msg);
int iam_msgSend(RestContext *ctx, IamMessage *msg, char *cryptid, char *signid);
int iam_msgSendArn(RestContext *ctx, IamMessage *msg, char *cryptid, char *signid, char *host, char *arn);
int iam_msgSendSqs(RestContext *rctx, IamMessage *msg, char *cryptid, char *signid);
int iam_msgSendSqsQueue(RestContext *rctx, IamMessage *msg, char *cryptid, char *signid, char *queueUrl);

IamMessage *iam_msgRecv(RestContext *ctx);
IamMessage *iam_msgParse();
char *iam_msgEncode(IamMessage *msg, char *cryptid, char *signid);
int iam_msgSendAzure(IamMessage *msg, char *cryptid, char *signid, char *namespace, char *topic);
int iam_msgInit(char *cfgfile);



#endif /* _iam_msg_h */

