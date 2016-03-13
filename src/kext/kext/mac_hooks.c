//
//  mac_hooks.c
//  ShellGuard
//
//  Created by v on 11/03/16.
//  Copyright © 2016 vivami. All rights reserved.
//

#include "mac_hooks.h"
#include "kext_control.h"
#include "definitions.h"
#include "whitelist.h"
#include "shellguard.h"

#include <sys/proc.h>
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <IOKit/IOLib.h>



extern int32_t state;


SLIST_HEAD(processes_slist, process_t);
static struct processes_slist process_list;

typedef struct process_t {
    char    procname[MAXPATHLEN+1];
    pid_t   pid;
    pid_t   ppid;
    SLIST_ENTRY(process_t) entries;
} process_t;

kern_return_t cleanup_list_structure(void);
kern_return_t store_new_process(const char* procname, pid_t pid, pid_t ppid);
char* get_process_path(pid_t pid);


static int hook_exec(kauth_cred_t cred,
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
                     size_t macpolicyattrlen )
{
    /* Some vars we need. */
    int32_t action = ALLOW;
    int32_t path_length = MAXPATHLEN;
    char procname[MAXPATHLEN+1] = {0};
    char path[MAXPATHLEN+1]     = {0};
    pid_t pid = -1;
    pid_t ppid = -1;
    char* procpath = NULL;
    
    if (vn_getpath(vp, path, &path_length) != 0 ) {
        LOG_ERROR("Can't build path to vnode.");
        /* Now what...? Just allowing the action for now... */
        return ALLOW;
    }
    
    pid = proc_selfpid();
    ppid = proc_selfppid();
    proc_name(pid, procname, sizeof(procname));
    
    LOG_DEBUG("New process: %s, pid: %d, ppid: %d.\n", path, pid, ppid);
    store_new_process(path, pid, ppid);
    
    switch (state) {
        case ENFORCING:
            if (is_shell_blocked(path)) {

                procpath = get_process_path(ppid);
                if (procpath == NULL) {
                    procpath = path;
                }
                action = filter(procname, procpath);
                if (action == DENY) {
                    LOG_INFO("Blocking execution of %s by %s.", path, procpath);
                    LOG_INFO("Killing (likely) malicious parent process.");
                    /* Send message to userland. */
                    kern_space_info_message kern_info_m = {0};
                    snprintf(kern_info_m.message, sizeof(kern_info_m.message) - 4, "%s;%s;", procpath, path);
                    kern_info_m.mode = ENFORCING;
                    queue_userland_data(&kern_info_m);
                    /* Also kill the malicious parent that tries to spawn the shell. */
                    proc_signal(pid, SIGKILL);
                }
            }
            break;
        case COMPLAINING:
            if (is_shell_blocked(path)) {
                char* procpath;
                procpath = get_process_path(ppid);
                if (procpath == NULL) {
                    procpath = path;
                }
                action = filter(procname, path);
                if (action == DENY) {
                    LOG_INFO("Complaining: execution of %s by %s.", path, procname);
                    LOG_INFO("Would kill (likely) malicious parent process.");
                    /* Also kill the malicious parent that tries to spawn the shell. */
                    /* Send message to userland. */
                    kern_space_info_message kern_info_m = {0};
                    snprintf(kern_info_m.message, sizeof(kern_info_m.message) - 4, "%s;%s;", procpath, path);
                    kern_info_m.mode = COMPLAINING;
                    queue_userland_data(&kern_info_m);
                    /* Eventually allow the action, because we will only complain. */
                    action = ALLOW;
                }
            }
            break;
        default:
            break;

    }
    if (procpath != NULL) {
        OSFree(procpath, sizeof(procpath), return_mallocTag());
    }

    return action;
}

/* Store new process so that we can retrieve its path later. */
kern_return_t store_new_process(const char* procname, pid_t pid, pid_t ppid)
{
    process_t *iterator = NULL;
    SLIST_FOREACH(iterator, &process_list, entries) {
        //LOG_DEBUG("Process: %s, pid: %d", iterator->procname, iterator->pid);
        if (iterator->pid == pid) {
            /* There is a process with the same PID. Reuse of PID means the previous process 
             * does not exsist anymore.
             */
            SLIST_REMOVE(&process_list, iterator, process_t, entries);
            OSFree(iterator, sizeof(process_t), return_mallocTag());
        }
    }
    process_t *new_entry = OSMalloc(sizeof(process_t), return_mallocTag());
    if (new_entry == NULL) {
        LOG_ERROR("Could not allocate memory for process structure.");
        return KERN_FAILURE;
    }
    memset(new_entry, 0, sizeof(process_t));
    new_entry->pid = pid;
    new_entry->ppid = ppid;
    strlcpy(new_entry->procname, procname, sizeof(new_entry->procname));
    SLIST_INSERT_HEAD(&process_list, new_entry, entries);
    return KERN_SUCCESS;
}


/* cleanup the process list memory. */
kern_return_t cleanup_list_structure(void)
{
    process_t *entry = NULL;
    process_t *next_entry = NULL;
    SLIST_FOREACH_SAFE(entry, &process_list, entries, next_entry) {
        SLIST_REMOVE(&process_list, entry, process_t, entries);
        OSFree(entry, sizeof(process_t), return_mallocTag());
    }
    return KERN_SUCCESS;
}


char* get_process_path(pid_t pid)
{
    process_t *entry = NULL;
    SLIST_FOREACH(entry, &process_list, entries) {
        if (entry->pid == pid) {
            char* procpath = OSMalloc(sizeof(char) * MAXPATHLEN+1, return_mallocTag());
            memset(procpath, 0, sizeof(char) * MAXPATHLEN+1);
            if (procpath == NULL) {
                LOG_ERROR("Could not allocate memory.");
            }
            /* entry->procname is already '\0' terminated. */
            strlcpy(procpath, entry->procname, sizeof(entry->procname));
            return procpath;
        }
    }
    return NULL;
}

/* Registers TrustedBSD MAC policy for ShellGuard. */
kern_return_t register_mac_policy(void *d)
{
    SLIST_INIT(&process_list);
    if (mac_policy_register(&shellguard_policy_conf, &shellguard_handle, d) != KERN_SUCCESS) {
        LOG_ERROR("Failed to start ShellGuard TrustedBSD module!");
        cleanup_list_structure();
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/* Unregisters TrustedBSD MAC policy for ShellGuard. */
kern_return_t unregister_mac_policy(void *d)
{
    kern_return_t res = 0;
    if ( (res = mac_policy_unregister(shellguard_handle)) != KERN_SUCCESS) {
        LOG_ERROR("Failed to unload ShellGuard TrustedBSD module: %d.", res);
        return KERN_FAILURE;
    }
    IOSleep(5000);
    cleanup_list_structure();
    return KERN_SUCCESS;
}



