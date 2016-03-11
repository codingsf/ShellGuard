//
//  mac_hooks.h
//  ShellGuard
//
//  Created by v on 11/03/16.
//  Copyright © 2016 vivami. All rights reserved.
//

#ifndef mac_hooks_h
#define mac_hooks_h

#include <mach/mach_types.h>

#define ALLOW   0
#define DENY    1


kern_return_t register_mac_policy(void *d);
kern_return_t unregister_mac_policy(void *d);



#endif /* mac_hooks_h */
