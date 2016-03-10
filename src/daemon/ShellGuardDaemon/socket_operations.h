#ifndef socket_operations_h
#define socket_operations_h

#include "shared_data.h"

UInt32 getControlIdentifier(int socket);
void init_dispatch_queues(int32_t socket);
void process_kernel_message(int32_t socket);
int32_t prepControlDataAndSend(int32_t socket, UInt32 cmd, UInt32 pid, const char* procname, rule_t* r);
rule_t* toRuleStruct(const char* procname, const char* action, uint32_t kauth_op, const char* path, bool root, uint32_t path_wildcard, uint32_t kauth_action);

dispatch_source_t ds;


#endif /* socket_operations_h */
