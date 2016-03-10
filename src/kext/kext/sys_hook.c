//
//  sys_hook.c
//  ShellGuard
//
//  Created by v on 10/03/16.
//  Copyright © 2016 vivami. All rights reserved.
//

#include "sys_hook.h"
#include "definitions.h"
#include "sysent.h"
#include "cpu_protections.h"
#include <mach/shared_region.h>
#include "proc.h"

void *_sysent_addr;
extern const int version_major;

#ifndef __arm__
#define	PAD_(t)	(sizeof(uint64_t) <= sizeof(t) \
? 0 : sizeof(uint64_t) - sizeof(t))
#else
#define	PAD_(t)	(sizeof(uint32_t) <= sizeof(t) \
? 0 : sizeof(uint32_t) - sizeof(t))
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
#define	PADL_(t)	0
#define	PADR_(t)	PAD_(t)
#else
#define	PADL_(t)	PAD_(t)
#define	PADR_(t)	0
#endif

struct execve_args {
    char fname_l_[PADL_(user_addr_t)]; user_addr_t fname; char fname_r_[PADR_(user_addr_t)];
    char argp_l_[PADL_(user_addr_t)]; user_addr_t argp; char argp_r_[PADR_(user_addr_t)];
    char envp_l_[PADL_(user_addr_t)]; user_addr_t envp; char envp_r_[PADR_(user_addr_t)];
};


struct posix_spawn_args {
    char pid_l_[PADL_(user_addr_t)]; user_addr_t pid; char pid_r_[PADR_(user_addr_t)];
    char path_l_[PADL_(user_addr_t)]; user_addr_t path; char path_r_[PADR_(user_addr_t)];
    char adesc_l_[PADL_(user_addr_t)]; user_addr_t adesc; char adesc_r_[PADR_(user_addr_t)];
    char argv_l_[PADL_(user_addr_t)]; user_addr_t argv; char argv_r_[PADR_(user_addr_t)];
    char envp_l_[PADL_(user_addr_t)]; user_addr_t envp; char envp_r_[PADR_(user_addr_t)];
};


//void filter(struct proc *p, struct args *u, int *r, int32_t syscall) {
//    
//}

// prototypes
int (*real_posix_spawn)(struct proc *, struct posix_spawn_args *, int *);
int (*real_execve)(struct proc *, struct execve_args *, int *);
int shellguard_posix_spawn(struct proc *, struct posix_spawn_args *, int *);
int shellguard_execve(struct proc *, struct execve_args *, int *);

int shellguard_posix_spawn(struct proc *p, struct posix_spawn_args *u, int *r) {
    char processname[MAXCOMLEN+1];
    pid_t pid = proc_pid(p);
    proc_name(pid, processname, sizeof(processname));
    LOG_DEBUG("SYS_posix_spawn by: %s, pid: %llu on %s", processname, u->pid, u->path);
    return real_posix_spawn(p, u, r);
}

int shellguard_execve(struct proc *p, struct execve_args *u, int *r) {
    char processname[MAXCOMLEN+1];
    pid_t pid = proc_pid(p);
    proc_name(pid, processname, sizeof(processname));
    LOG_DEBUG("SYS_execve by: %s, on %s", processname, u->fname);
    return real_execve(p, u, r);;
}


kern_return_t hook_syscalls() {
    mach_vm_address_t kernel_base = 0;
    if ((_sysent_addr = find_sysent(&kernel_base)) == NULL) {
        LOG_ERROR("Could not determine sysent location. Fatal. Aborting.");
        return KERN_FAILURE;
    }
    enable_kernel_write();
    // restore the pointer to the original function

    struct sysent_yosemite *sysent = (struct sysent_yosemite*)_sysent_addr;
    real_execve = (void*)sysent[SYS_execve].sy_call;
    sysent[SYS_execve].sy_call = (sy_call_t*)shellguard_execve;
    LOG_DEBUG("Hooked SYS_execve");
    real_posix_spawn = (void*)sysent[SYS_posix_spawn].sy_call;
    sysent[SYS_posix_spawn].sy_call = (sy_call_t*)shellguard_posix_spawn;
    LOG_DEBUG("Hooked SYS_posix_spawn");
    
    disable_kernel_write();
    return KERN_SUCCESS;
}

kern_return_t unhook_syscalls() {
    if (_sysent_addr == NULL) {
        LOG_ERROR("Sysent is NULL. Fatal. Aborting.");
        return KERN_FAILURE;
    }
    
    enable_kernel_write();
    if ((real_posix_spawn == NULL) || (real_execve == NULL)) {
        LOG_ERROR("No pointer available for original syscall functions!");
        disable_kernel_write();
        return KERN_FAILURE;
    }
    struct sysent_yosemite *sysent = (struct sysent_yosemite*)_sysent_addr;
    sysent[SYS_execve].sy_call = (sy_call_t*)real_execve;
    LOG_DEBUG("Unhooked SYS_execve");
    sysent[SYS_posix_spawn].sy_call = (sy_call_t*)real_posix_spawn;
    LOG_DEBUG("Unhooked SYS_posix_spawn");
    
    return KERN_SUCCESS;
}