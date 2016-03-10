//
//  sys_hook.h
//  ShellGuard
//
//  Created by v on 10/03/16.
//  Copyright © 2016 vivami. All rights reserved.
//

#ifndef sys_hook_h
#define sys_hook_h

//#include <sys/appleapiopts.h>
//#include <sys/cdefs.h>
//#include <sys/types.h>
//#include <sys/wait.h>
#include <mach/shared_region.h>
#include "proc.h"
//#include <sys/socket.h>

#define	SYS_execve         59
#define	SYS_posix_spawn    244


//#ifndef __arm__
//#define	PAD_(t)	(sizeof(uint64_t) <= sizeof(t) \
//? 0 : sizeof(uint64_t) - sizeof(t))
//#else
//#define	PAD_(t)	(sizeof(uint32_t) <= sizeof(t) \
//? 0 : sizeof(uint32_t) - sizeof(t))
//#endif
//#if BYTE_ORDER == LITTLE_ENDIAN
//#define	PADL_(t)	0
//#define	PADR_(t)	PAD_(t)
//#else
//#define	PADL_(t)	PAD_(t)
//#define	PADR_(t)	0
//#endif
//
//struct execve_args {
//    char fname_l_[PADL_(user_addr_t)]; user_addr_t fname; char fname_r_[PADR_(user_addr_t)];
//    char argp_l_[PADL_(user_addr_t)]; user_addr_t argp; char argp_r_[PADR_(user_addr_t)];
//    char envp_l_[PADL_(user_addr_t)]; user_addr_t envp; char envp_r_[PADR_(user_addr_t)];
//};
//
//
//struct posix_spawn_args {
//    char pid_l_[PADL_(user_addr_t)]; user_addr_t pid; char pid_r_[PADR_(user_addr_t)];
//    char path_l_[PADL_(user_addr_t)]; user_addr_t path; char path_r_[PADR_(user_addr_t)];
//    char adesc_l_[PADL_(user_addr_t)]; user_addr_t adesc; char adesc_r_[PADR_(user_addr_t)];
//    char argv_l_[PADL_(user_addr_t)]; user_addr_t argv; char argv_r_[PADR_(user_addr_t)];
//    char envp_l_[PADL_(user_addr_t)]; user_addr_t envp; char envp_r_[PADR_(user_addr_t)];
//};

kern_return_t hook_syscalls();
kern_return_t unhook_syscalls();
#endif /* sys_hook_h */
