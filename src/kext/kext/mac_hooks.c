//
//  mac_hooks.c
//  ShellGuard
//
//  Created by v on 11/03/16.
//  Copyright © 2016 vivami. All rights reserved.
//
//
//  TrustedBSD MAC hooks for the execution of processes. This is where the
//  ShellGuard magic happens...
//
//

#include "mac_hooks.h"
#include "kext_control.h"
#include "definitions.h"
#include "filter.h"
#include "shellguard.h"

#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <sys/vnode.h>
#include <IOKit/IOLib.h>



static const char   XPCPROXY[]      = "/usr/libexec/xpcproxy";
static uint32_t     LAUNCHD_PID     = 1;
extern int32_t      state;
/* This mutex protects the LIST that holds the path's processes. */
static lck_mtx_t    *proc_list_lock = NULL;
static SInt32       g_activation_count = 0;


LIST_HEAD(processes_LIST_head, process_t) process_list_head = LIST_HEAD_INITIALIZER(process_list_head);

typedef struct process_t {
    char    procname[MAXPATHLEN+1];
    pid_t   pid;
    pid_t   ppid;
    LIST_ENTRY(process_t) entries;
} process_t;

kern_return_t cleanup_list_structure(void);
kern_return_t store_new_process(const char* procname, pid_t pid, pid_t ppid);
kern_return_t send_to_userspace(char* path, uint32_t p, char* procpath,uint32_t ppid, uint32_t mode);
int32_t get_process_path(pid_t pid, char* path_ptr);
uint32_t get_qattr_flags(vnode_t vnode);
uint32_t signed_binary(vnode_t vp, const char* path);

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
    int32_t action              = ALLOW;
    int32_t path_length         = MAXPATHLEN;
    char procname[MAXPATHLEN]   = {0};
    char procpath[MAXPATHLEN]   = {0};
    char pprocpath[MAXPATHLEN]  = {0};
    pid_t pid                   = -1;
    pid_t ppid                  = -1;
    pid_t pgid                  = -1;
    
    
    /* Keep track of how many threads currently use this function. */
    (void) OSIncrementAtomic(&g_activation_count);
    
    if (vn_getpath(vp, procpath, &path_length) != 0 ) {
        LOG_ERROR("Can't build path to vnode.");
        /* Now what...? Just allowing the action for now... */
        goto exit;
    }
    
    pid = proc_selfpid();
    ppid = proc_selfppid();
    pgid = proc_selfpgrpid();
    proc_name(pid, procname, sizeof(procname));
    
    if (get_process_path(ppid, pprocpath) != 0) {
        /* We don't know the path of the parent process. This is unlikely to happen,
         * since ShellGuard starts before pretty much any other userland process (in production env).
         * However, in testing phase it may occur processes were already running before we came into the kernel.
         */
        if (ppid == 1)
            strncpy(pprocpath, "/sbin/launchd", MAXPATHLEN);
        else if (ppid == 0)
            strncpy(pprocpath, "kernel_task", MAXPATHLEN);
        else
            strncpy(pprocpath, "Unknown process", MAXPATHLEN);
    }
    LOG_INFO("New process: %s (%d/%d) by %s (%d)", procpath, pid, pgid, pprocpath, ppid);
    
    
    /* Allow process executions from xpcproxy and launchd. */
    if (strcmp(procpath, XPCPROXY) == 0) {
        goto exit;
    }

    
    store_new_process(procpath, pid, ppid);
    
    /* We're not interested in authorizing processes spawned by launchd. */
//    if (ppid == LAUNCHD_PID || pid == LAUNCHD_PID) {
//        goto exit;
//    }
    
    
    
    if (is_shell_blocked(procpath)) {
        if (get_process_path(ppid, pprocpath) != 0) {
            /* We don't know the path of the parent process. This is unlikely to happen,
             * since ShellGuard starts before pretty much any other userland process (in production env).
             * However, in testing phase it may occur processes were already running before we came into the kernel.
             */
            if (ppid == 1)
                strncpy(pprocpath, "/sbin/launchd", MAXPATHLEN);
            else if (ppid == 0)
                strncpy(pprocpath, "kernel_task", MAXPATHLEN);
            else
                strncpy(pprocpath, "Unknown process", MAXPATHLEN);
        }
        /* Decide what the action for this process and parent process will be... */
        action = filter(pprocpath, procpath);
    }
    
    switch (state) {
        case ENFORCING:
            if (action == DENY) {
                
                /* Send message to userland. */
                send_to_userspace(procpath, pid, pprocpath, ppid, ENFORCING);
                /* Also kill the malicious parent (apart from launchd or kernel) that tries to spawn the shell. */
                if ((ppid != 1) && (ppid != 0)) {
                    proc_signal(pid, SIGKILL);
                    proc_signal(ppid, SIGKILL);
                    LOG_INFO("Blocking execution of %s (%d/%d) by %s (%d). Killing (likely) malicious parent process.", procpath, pid, pgid, pprocpath, ppid);
                } else {
                    proc_signal(pid, SIGKILL);
                    LOG_INFO("Blocking execution of %s (%d/%d) by %s (%d), spawned by launchd.", procpath, pid, pgid, pprocpath, ppid);
                }
            }
            break;
        case COMPLAINING:
            if (action == DENY) {
                LOG_INFO("Complaining: execution of %s (%d/%d) by %s (%d). Would kill (likely) malicious parent process.", procpath, pid, pgid, pprocpath, ppid);
                /* Send message to userland. */
                send_to_userspace(procpath, pid, pprocpath, ppid, COMPLAINING);
                /* Eventually allow the action, because we will only complain. */
                action = ALLOW;
            }
            break;
        default:
            break;
    }
    
exit:
    (void) OSDecrementAtomic(&g_activation_count);
    
    return action;
}

#pragma mark -
#pragma mark TrustedBSD Hooks helper functions

/* Store new process so that we can retrieve its path later. */
kern_return_t store_new_process(const char* procname, pid_t pid, pid_t ppid)
{
    lck_mtx_lock(proc_list_lock);
    
    process_t *iterator = NULL;
    process_t *next_iterator = NULL;
    LIST_FOREACH_SAFE(iterator, &process_list_head, entries, next_iterator) {
        if (iterator->pid == pid) {
            LOG_DEBUG("There is a process with the same PID %d: %s. Removing.", iterator->pid, iterator->procname);
            /* There is a process with the same PID. Reuse of PID means the previous process 
             * does not exsist anymore.
             */
            LIST_REMOVE(iterator, entries);
            OSFree(iterator, sizeof(process_t), return_mallocTag());
        }
    }
    process_t *new_entry = OSMalloc(sizeof(process_t), return_mallocTag());
    if (new_entry == NULL) {
        LOG_ERROR("Could not allocate memory for process structure.");
        lck_mtx_unlock(proc_list_lock);
        return KERN_FAILURE;
    }
    memset(new_entry, 0, sizeof(process_t));
    new_entry->pid = pid;
    new_entry->ppid = ppid;
    strlcpy(new_entry->procname, procname, MAXPATHLEN);
    LIST_INSERT_HEAD(&process_list_head, new_entry, entries);
    
    lck_mtx_unlock(proc_list_lock);
    return KERN_SUCCESS;
}


/* cleanup the process list memory. */
kern_return_t cleanup_list_structure(void)
{
    lck_mtx_lock(proc_list_lock);
    
    process_t *entry = NULL;
    process_t *next_entry = NULL;
    LIST_FOREACH_SAFE(entry, &process_list_head, entries, next_entry) {
        LIST_REMOVE(entry, entries);
        OSFree(entry, sizeof(process_t), return_mallocTag());
    }
    
    lck_mtx_unlock(proc_list_lock);
    return KERN_SUCCESS;
}


/* Get process path from the list of currently running processes. This list contains only
 * the processes that executed *after* ShellGuard was loaded into the kernel.
 */
int32_t get_process_path(pid_t pid, char* path_ptr)
{
    lck_mtx_lock(proc_list_lock);
    
    process_t *entry = NULL;
    process_t *next_entry = NULL;
    LIST_FOREACH_SAFE(entry, &process_list_head, entries, next_entry) {
        if (entry->pid == pid) {
            strlcpy(path_ptr, entry->procname, MAXPATHLEN);
            lck_mtx_unlock(proc_list_lock);
            return 0;
        }
    }
    lck_mtx_unlock(proc_list_lock);
    return 1;
}


/* Sends message/event to userspace over socket. */
kern_return_t send_to_userspace(char* path, uint32_t pid, char* procpath,uint32_t ppid, uint32_t mode)
{
    kern_space_info_message kern_info_m = {0};
    snprintf(kern_info_m.message, sizeof(kern_info_m.message) - 4, "%s;%s;", procpath, path);
    kern_info_m.mode = mode;
    kern_info_m.pid = pid;
    kern_info_m.ppid = ppid;
    kern_info_m.signed_bin = SIGNED;
    queue_userland_data(&kern_info_m);
    return KERN_SUCCESS;
}


/* Checks if the binary is signed. */
uint32_t signed_binary(vnode_t vp, const char* path)
{
    uint32_t has_q_flags = get_qattr_flags(vp);
    
    if (has_q_flags == FALSE) {
        if (strncmp("/Volumes/", path, strlen("/Volumes/")) == 0) {
            return DMG_LOADED;
        } else {
            //LOG_DEBUG("No quarantine flags.");
            return DEFER;
        }
    }
    /* CoreServicesUIAgent (user-mode) sets flags to 0x40 when user clicks 'allow', so just allow such binaries. */
    if ((has_q_flags & 0x40) != 0) {
        return PREV_APPROVED;
    }
    
    /* Lock vnode/ */
    lck_mtx_lock((lck_mtx_t *)vp);
    unsigned char* offsetPointer = (unsigned char*)(vnode_t)vp;
    
    /* Get pointer to struct ubc_info in vnode struct ->disasm from kernel:  mov rax, [vnode+70h] */
    offsetPointer += 0x70;
    if(*(unsigned long*)(offsetPointer) == 0) {
        lck_mtx_unlock((lck_mtx_t *)vp);
        return DEFER;
    }
    //LOG_DEBUG("vnode 'vu_ubcinfo': %p, points to: %p\n", offsetPointer, (void*)*(unsigned long*)(offsetPointer));
    
    /* Get addr of struct ubc_info. */
    offsetPointer = (unsigned char*)*(unsigned long*)(offsetPointer);
    
    /* Get pointer to cs_blob struct from struct ubc_info ->disasm from kernel: mov rax, [ubc_info+50h] */
    offsetPointer += 0x50;
    
    //LOG_DEBUG("ubc_info 'cs_blob': %p\n", offsetPointer);
    
    //non-null csBlogs means process's binary is signed
    // ->note: yah, its a limitation that the binary could be signed, but invalidly
    if(*(unsigned long*)(offsetPointer) == 0) {
        lck_mtx_unlock((lck_mtx_t *)vp);
        return SIGNED;
    }
    
    lck_mtx_unlock((lck_mtx_t *)vp);
    
    /* Binary is from the Internet and unsigned. */
    return UNSIGNED;
}

/* Check if binary has Quarantine flags set, meaning it has been downloaded from the Internet. */
uint32_t get_qattr_flags(vnode_t vnode)
{
    u_int32_t qFlags    = 0;
    char* qAttr         = NULL;
    size_t qAttrLength  = 0;
    
    qAttr = (char*)OSMalloc(QATTR_SIZE, return_mallocTag());
    if (NULL == qAttr) {
        goto exit;
    }
    
    /* Get quarantine attributes. If this 'fails', simply means binary doesn't have quarantine attributes. */
    if (mac_vnop_getxattr(vnode, QFLAGS_STRING_ID, qAttr, QATTR_SIZE-1, &qAttrLength) != 0) {
        goto exit;
    }

    qAttr[qAttrLength] = 0x0;
    LOG_DEBUG("Quarantine attributes: %s", qAttr);
    
    /* grab flags, format will look something like: 0002;567c4986;Safari;8122B05F-C448-4FA4-B2CC-30A8E50BE65B */
    if (sscanf(qAttr, "%04x", &qFlags) != 1) {
        goto exit;
    }
    //LOG_DEBUG("value for %s -> %x...\n", QFLAGS_STRING_ID, qFlags);
    
exit:
    if (NULL != qAttr) {
        OSFree(qAttr, QATTR_SIZE, return_mallocTag());
        qAttr = NULL;
    }
    
    return qFlags;
}


#pragma mark -
#pragma mark TrustedBSD Hooks register functions

/* Registers TrustedBSD MAC policy for ShellGuard. */
kern_return_t register_mac_policy(void *d)
{
    lck_grp_attr_t*	grp_attrib = NULL;
    lck_attr_t*		lck_attrb  = NULL;
    lck_grp_t*		lck_group  = NULL;
    
    grp_attrib = lck_grp_attr_alloc_init();
    lck_group = lck_grp_alloc_init("mbuf_tag_allocate_id", grp_attrib);
    lck_grp_attr_free(grp_attrib);
    lck_attrb = lck_attr_alloc_init();
    
    proc_list_lock = lck_mtx_alloc_init(lck_group, lck_attrb);
    
    lck_grp_free(lck_group);
    lck_attr_free(lck_attrb);
    
    
    LIST_INIT(&process_list_head);
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
    
    /* Wait for any threads within hook_exec to stop using hook_exec. */
    do {
        struct timespec one_sec;
        one_sec.tv_sec  = 1;
        one_sec.tv_nsec = 0;
        (void) msleep(&g_activation_count, NULL, PUSER, "com.shellguard.unregister_policy", &one_sec);
    } while (g_activation_count > 0);
    
    cleanup_list_structure();
    
    return KERN_SUCCESS;
}



