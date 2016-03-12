
#ifndef mac_hooks_h
#define mac_hooks_h

#include <mach/mach_types.h>


kern_return_t register_mac_policy(void *d);
kern_return_t unregister_mac_policy(void *d);



#endif /* mac_hooks_h */
