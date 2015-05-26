// azure defs

typedef struct AzureMessage_ {
   char *msg;
   char *locktoken;
   char *seqno;
   char *namespace;
   char *topic;
   char *subscription;
} AzureMessage;
   
AzureMessage *azure_recvMessage(char *namespace, char *topic, char *subscription);
int azure_sendMessage(char *sub, char *msg, int msgl, char *namespace, char *topic);
int azure_deleteMessage(AzureMessage *msg);
int azure_init(char *keyn, char *keyv, char *ns, char *topic, char *sub);


