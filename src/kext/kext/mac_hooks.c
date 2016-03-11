//
//  mac_hooks.c
//  ShellGuard
//
//  Created by v on 11/03/16.
//  Copyright © 2016 vivami. All rights reserved.
//

#include "mac_hooks.h"
#include "definitions.h"

#include <sys/proc.h>
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <sys/vnode.h>


static int hook_exec(
                     kauth_cred_t cred,
                     struct vnode *vp,
                     struct vnode *scriptvp,
                     struct label *vnodelabel,
                     struct label *scriptlabel,
                     struct label *execlabel,	/* NULLOK */
                     struct componentname *cnp,
                     u_int *csflags,
                     void *macpolicyattr,
                     size_t macpolicyattrlen );


#pragma mark -
#pragma mark TrustedBSD Hooks


static struct mac_policy_ops shellguard_ops = {
    .mpo_vnode_check_exec = hook_exec
};

mac_policy_handle_t shellguard_handle;

static struct mac_policy_conf shellguard_policy_conf = {
    .mpc_name            = "shellguard",
    .mpc_fullname        = "ShellGuard Kernel Driver",
    .mpc_labelnames      = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops             = &shellguard_ops,
    .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK, /* NOTE: this allows to unload, good idea to remove in release */
    .mpc_field_off       = NULL,
    .mpc_runtime_flags   = 0
};

/* Hooks SYS_execve and SYS_posix_spawn. */
static int hook_exec(kauth_cred_t cred,
                     struct vnode *vp,
                     struct vnode *scriptvp,
                     struct label *vnodelabel,
                     struct label *scriptlabel,
                     struct label *execlabel,	/* NULLOK */
                     struct componentname *cnp,
                     u_int *csflags,
                     void *macpolicyattr,
                     size_t macpolicyattrlen ){

    /* Some vars we need. */
    int32_t path_length = MAXPATHLEN;
    char procname[MAXPATHLEN+1] = {0};
    char path[MAXPATHLEN+1]     = {0};
    pid_t pid = -1;
    pid_t ppid = -1;
    
    if (vn_getpath(vp, path, &path_length) != 0 ) {
        LOG_ERROR("Can't build path to vnode.");
        /* Now what...? Just allowing the action for now... */
        return 0;
    }
    
    pid = proc_selfpid();
    ppid = proc_selfppid();
    proc_name(pid, procname, sizeof(procname));
    LOG_DEBUG("New process: %s, pid: %d, ppid: %d.\n", path, pid, ppid);
    
    if (strncmp("/bin/sh", path, strlen("/bin/sh")) == 0) {
        //kill the process and its malicious parent.
        LOG_DEBUG("Killed %s, pid: %d, ppid: %d", path, pid, ppid);
        LOG_DEBUG("Killed parent process pid: %d", pid);
        proc_signal(pid, SIGKILL);
        return DENY;
    }
    return ALLOW;
}


/* Registers TrustedBSD MAC policy for ShellGuard. */
kern_return_t register_mac_policy(void *d) {
    if (mac_policy_register(&shellguard_policy_conf, &shellguard_handle, d) != KERN_SUCCESS) {
        LOG_ERROR("Failed to start ShellGuard TrustedBSD module!");
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/* Unregisters TrustedBSD MAC policy for ShellGuard. */
kern_return_t unregister_mac_policy(void *d) {
    kern_return_t res = 0;
    if ( (res = mac_policy_unregister(shellguard_handle)) != KERN_SUCCESS) {
        LOG_ERROR("Failed to unload ShellGuard TrustedBSD module: %d.", res);
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}



