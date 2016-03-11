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


kern_return_t register_mac_policy(void *d);
kern_return_t unregister_mac_policy(void *d);

#endif /* mac_hooks_h */
