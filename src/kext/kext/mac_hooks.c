//
//  mac_hooks.c
//  ShellGuard
//
//  Created by v on 11/03/16.
//  Copyright © 2016 vivami. All rights reserved.
//

#include "mac_hooks.h"
#include "definitions.h"

//#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <kern/task.h>
#include <sys/proc.h>
#include <kern/thread.h>
#include <kern/locks.h>
#include <kern/clock.h>
#include <sys/vm.h>

#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <Availability.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <libkern/OSMalloc.h>
#include <sys/kauth.h>
#include <sys/proc.h>




#pragma mark -
#pragma mark TrustedBSD Hooks

//static int hook_exec(kauth_cred_t cred, struct vnode *vp, struct label *label, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen);


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


static struct mac_policy_ops shellguard_ops =
{
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

/* NOTE: this function prototype changed from 10.8 to 10.9 and also 10.10
 *       so it needs to be specific for each version and use each SDK.
 *       there are other functions that suffered the same fate
 *       this is probably the main reason why Apple is closing TrustedBSD access
 *
 * A return value of 0 means access is granted or check deferred to next hook.
 * A value higher than zero means access is refused right away.
 */
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
                     size_t macpolicyattrlen )
{

    
    //struct vnode_attr vap = {0};
    vfs_context_t context = vfs_context_create(NULL);
    if (context == NULL)
    {
        LOG_ERROR("Failed to create context.");
        return 0;
    }
    //path length
    int32_t path_length = MAXPATHLEN;
    
    char procname[MAXPATHLEN+1] = {0};
    char path[MAXPATHLEN+1]     = {0};
    pid_t pid = -1;
    pid_t ppid = -1;
    
    if (vn_getpath(vp, path, &path_length) != 0 )
    {
        LOG_ERROR("Can't build path to vnode.");
        /* XXX: what action here???? */
        return 0;
    }
    
    pid = proc_selfpid();
    ppid = proc_selfppid();
    proc_name(pid, procname, sizeof(procname));
    LOG_DEBUG("New process: %s, pid: %d, ppid: %d.\n", path, pid, ppid);
    
    
    
//    /* initialize the structure fields we are interested in */
//    VATTR_INIT(&vap);
//    VATTR_WANTED(&vap, va_mode);
//    if ( vnode_getattr(vp, &vap, context) != 0 )
//    {
//        LOG_ERROR("Failed to get vnode attributes.");
//        /* XXX: what action here???? */
//    }
//    vfs_context_rele(context);
//    
//    /* verify if binary has any SUID bit set */
//    if (vap.va_mode & S_ISUID || vap.va_mode & S_ISGID)
//    {
//        /* retrieve the UID of the process so we whitelist per user */
//        uid_t target_uid = kauth_getuid();
//        
//        struct whitelist_entry *entry = NULL;
//        /* verify if this vnode is whitelisted */
//        SLIST_FOREACH(entry, &g_whitelist, entries)
//        {
//            /* verify that the vnodes match and also the UID because we want whitelist per user and not global */
//            if (entry->vnode == vp && entry->uid == kauth_getuid())
//            {
//                /* there's only whitelisting so let it proceed */
//                return 0;
//            }
//        }
//        
//        struct userland_event event = {0};
//        
//        int pathbuff_len = sizeof(event.path);
//        
//        if ( vn_getpath(vp, event.path, &pathbuff_len) != 0 )
//        {
//            ERROR_MSG("Can't build path to vnode.");
//            /* XXX: what action here???? */
//        }
//        
//        /* XXX: gather more information about both processes? */
//        proc_t target_proc = current_proc();
//        if (target_proc == (struct proc *)0)
//        {
//            ERROR_MSG("Couldn't find process for task!");
//            return 0;
//        }
//        /* retrieve parent information */
//        /* unfortunately there's no function to get the vnode from a proc_t without some disassembly magic */
//        /* a new function for this was introduced in Yosemite */
//        pid_t parent_pid = proc_ppid(target_proc);
//        proc_name(parent_pid, event.parent_name, sizeof(event.parent_name));
//        /* notify userland */
//        DEBUG_MSG("Trying to execute suid binary %s with parent %s.", event.path, event.parent_name);
//        event.action = kDenySuid;
//        event.pid = proc_pid(target_proc);
//        event.ppid = parent_pid;
//        event.uid = target_uid;
//        /* parent info */
//        /* XXX: not sure if there's an easier way to get this info */
//        proc_t parent_proc = proc_find(parent_pid);
//        if (parent_proc != (struct proc*)0)
//        {
//            kauth_cred_t cred = kauth_cred_proc_ref(parent_proc);
//            if ( IS_VALID_CRED(cred) != 0 )
//            {
//                /* retrieve parent UID */
//                event.puid = kauth_cred_getuid(cred);
//                /* release references */
//                kauth_cred_unref(&cred);
//            }
//            /* release references */
//            proc_rele(parent_proc);
//        }
//        /* if we have a connection with userland we should wait for response */
//        if (g_connection_to_userland)
//        {
//            event.active = 1;
//            /*  send request to userland */
//            queue_userland_data(&event);
//            /*
//             * now wait for response - if we don't get a response default is to deny access
//             * unless we are still not connected to userland
//             */
//            struct timespec waittime = {0};
//            int crap;
//            waittime.tv_sec  = 0;
//            waittime.tv_nsec = USERLAND_RESPONSE_PERIOD;
//            int attempts = 0;
//            enum action_t auth_status = -1;
//            while (1)
//            {
//                msleep(&crap, NULL, PUSER, "suid", &waittime);
//                if ( get_authorization_status(event.pid, &auth_status) == 0 )
//                {
//                    ERROR_MSG("Found return result!");
//                    if (auth_status == kWhitelistSuid)
//                    {
//                        /* add to the list */
//                        struct whitelist_entry *new_entry = OSMalloc(sizeof(struct whitelist_entry), g_osmalloc_tag);
//                        if (new_entry != NULL)
//                        {
//                            new_entry->vnode = vp;
//                            new_entry->uid = target_uid;
//                            SLIST_INSERT_HEAD(&g_whitelist, new_entry, entries);
//                        }
//                        /* set the status to allow because whitelist means always access */
//                        auth_status = kAllowSuid;
//                    }
//                    return auth_status;
//                }
//                /* timeout exceed return default value */
//                if (attempts > USERLAND_TIMEOUT_COUNT)
//                {
//                    DEBUG_MSG("Return result for PID %d not found.", event.pid);
//                    return DEFAULT_POLICY;
//                }
//                attempts++;
//            }
//        }
//        /* userland daemon still not connected so we take note but authorize anyways */
//        else
//        {
//            /* just queue internally to send when connected */
//            enqueue_to_event(&g_to_queue, &event);
//            /* always authorize */
//            return 0;
//        }
//    }
    return 0;
}


kern_return_t register_mac_policy(void *d) {
    if (mac_policy_register(&shellguard_policy_conf, &shellguard_handle, d) != KERN_SUCCESS) {
        LOG_ERROR("Failed to start ShellGuard TrustedBSD module!");
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

kern_return_t unregister_mac_policy(void *d) {
    kern_return_t res = 0;
    if ( (res = mac_policy_unregister(shellguard_handle)) != KERN_SUCCESS) {
        LOG_ERROR("Failed to unload ShellGuard TrustedBSD module: %d.", res);
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}



