
#ifndef mac_hooks_h
#define mac_hooks_h

#include <mach/mach_types.h>
#include <sys/proc.h>

kern_return_t register_mac_policy(void *d);
kern_return_t unregister_mac_policy(void *d);
int32_t get_process_path(pid_t pid, char* path_ptr);


#endif /* mac_hooks_h */
