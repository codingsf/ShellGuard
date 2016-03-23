#ifndef socket_operations_h
#define socket_operations_h

#include "shared_data.h"

UInt32 get_control_identifier(int socket);
void init_dispatch_queues(int32_t socket);
void process_kernel_message(int32_t socket);
int32_t send_to_kernel(int socket, UInt32 cmd, entry_t* e);
entry_t* toEntryStruct(const char* procname, const char* shell);
dispatch_source_t ds;


#endif /* socket_operations_h */
