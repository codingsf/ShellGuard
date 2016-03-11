
#include "shellguard.h"
#include "kauth_controls.h"
#include "definitions.h"
#include "string_ops.h"
#include "kext_control.h"

#include <IOKit/IOLib.h>
#include <sys/vnode.h>
#include <sys/proc.h>


static int create_vnode_path(vnode_t vp, char **vpPathPtr);
static int create_vnode_action_string(kauth_action_t action, boolean_t isDir, char ** actionStrPtr, size_t * actionStrBufSizePtr);


/* some globals */
kauth_listener_t kauthListener = NULL;
static SInt32 gActivationCount = 0;

static pid_t monitoring_pid = 0;
static uint32_t mode = 0;
char* monitoring_proc = NULL;


enum {
    kActionStringMaxLength = 16384
};

#pragma mark -
#pragma mark KAuth listeners and helpers

/*
 * KAuth Vnode callback/listener. Gets called upon every Vnode/File System operation. 
 * Based on ShellGuard's mode, this function will determine whether the operation should be logged
 * or is denied/allowed by ShellGuard's rules.
 */
static int vnode_callback(kauth_cred_t    credential,
                          void *          idata,
                          kauth_action_t  action,
                          uintptr_t       arg0,
                          uintptr_t       arg1,
                          uintptr_t       arg2,
                          uintptr_t       arg3) {
    //declare a bunch of variables we may later need..
    int             err;
    vfs_context_t   context;
    vnode_t         vp;
    vnode_t         dvp;
    char *          vpPath;
    char *          dvpPath;
    boolean_t       isDir;
    char *          actionStr;
    size_t          actionStrBufSize;
    char            procname[MAXPATHLEN+1] = {0};
    int             auth_status;
    actionStrBufSize = 0;
    
    (void) OSIncrementAtomic(&gActivationCount);
    
    context = (vfs_context_t) arg0;
    vp      = (vnode_t) arg1;
    dvp     = (vnode_t) arg2;
    
    // by default, defer the action
    auth_status = KAUTH_RESULT_DEFER;
    vpPath  = NULL;
    dvpPath = NULL;
    actionStr = NULL;
    
    // get path of vnode
    err = create_vnode_path(vp, &vpPath);
    
    if (err == 0) {
        // get path of directory vnode
        err = create_vnode_path(dvp, &dvpPath);
    }
    
    // create human readable string of occured action
    if (err == 0) {
        if (vp != NULL) {
            isDir = ( vnode_vtype(vp) == VDIR );
        } else {
            isDir = FALSE;
        }
        err = create_vnode_action_string(action, isDir, &actionStr, &actionStrBufSize);
    }
    
    pid_t pid = proc_selfpid();
    pid_t ppid = proc_selfppid();
    
    proc_name(pid, procname, MAXPATHLEN+1);
    
    
    switch (mode) {
        case MONITOR_PID:
            if ((monitoring_pid != 0) && (monitoring_pid == pid)) {
                if (err == 0 && (vpPath != NULL)) {
                    LOG_INFO("; action=%s; bits=%s; uid=%ld; pid=%d; procname=%s; vp=%s; dvp=%s\n",
                             actionStr,
                             byte_to_binary(action),
                             (long) kauth_cred_getuid(vfs_context_ucred(context)),
                             pid,
                             procname,
                             (vpPath  != NULL) ?  vpPath : "<null>",
                             (dvpPath != NULL) ? dvpPath : "<null>"
                             );
                    if (kauth_cred_getuid(credential) == 0) {
                        LOG_DEBUG("ROOT OPERATION!!");
                    }
                    if (ppid == 0) {
                        LOG_DEBUG("ROOT OPERATION!!");
                    }
                }
            }
            break;
        case MONITOR_PROC:
            if ((monitoring_proc != NULL) && (monitoring_pid == 0)) {
                if (strcmp(procname, monitoring_proc) == 0) {
                    if (err == 0 && (vpPath != NULL)) {
//                        LOG_INFO("action=%s, bits=%s, int=%d, uid=%ld, pid=%d, procname=%s, vp=%s, dvp=%s\n",
//                                 actionStr,
//                                 byte_to_binary(action),
//                                 action,
//                                 (long) kauth_cred_getuid(vfs_context_ucred(context)),
//                                 pid,
//                                 procname,
//                                 (vpPath  != NULL) ?  vpPath : "<null>",
//                                 (dvpPath != NULL) ? dvpPath : "<null>"
//                                 );
                        LOG_INFO("; action=%s; bits=%s; int=%d; uid=%ld; pid=%d; procname=%s; vp=%s; dvp=%s\n",
                                 actionStr,
                                 byte_to_binary(action),
                                 action,
                                 (long) kauth_cred_getuid(vfs_context_ucred(context)),
                                 pid,
                                 procname,
                                 (vpPath  != NULL) ?  vpPath : "<null>",
                                 (dvpPath != NULL) ? dvpPath : "<null>"
                                 );
                    }
                }
            }
        case MONITOR_OFF:
            auth_status = KAUTH_RESULT_DEFER;
            break;
        case ENFORCING:
            if (!filter(procname, actionStr, action, vpPath)) {
                
                /* Reporting to userland. */
                kern_space_info_message kern_info_m = {0};
                snprintf(kern_info_m.message, sizeof(kern_info_m.message) - 4, "%s;%s;%s", procname, actionStr, vpPath);
                kern_info_m.mode = ENFORCING;
                queue_userland_data(&kern_info_m);
                
                LOG_INFO("Blocking %s, %s, %s", procname, actionStr, vpPath);
                /* DENY action, because we are enforcing. */
                auth_status = KAUTH_RESULT_DENY;
            } else
                auth_status = KAUTH_RESULT_DEFER;
            break;
        case ENFORCING_OFF:
            auth_status = KAUTH_RESULT_DEFER;
            break;
        case COMPLAINING:
            if (!filter(procname, actionStr, action, vpPath)) {
                
                /* Reporting to userland. */
                kern_space_info_message kern_info_m = {0};
                snprintf(kern_info_m.message, sizeof(kern_info_m.message) - 4, "%s;%s;%s", procname, actionStr, vpPath);
                kern_info_m.mode = COMPLAINING;
                queue_userland_data(&kern_info_m);
                
                LOG_INFO("COMPLAIN: %s, %s, %s", procname, actionStr, vpPath);
                /* DEFER action, because we are only complaining. */
                auth_status = KAUTH_RESULT_DEFER;
            } else
                auth_status = KAUTH_RESULT_DEFER;
            break;
        case COMPLAINING_OFF:
            auth_status = KAUTH_RESULT_DEFER;
            break;
        default:
            auth_status = KAUTH_RESULT_DEFER;
            break;
    }
    
    // clean up
    if (actionStr != NULL) {
        OSFree(actionStr, (uint32_t) actionStrBufSize, return_mallocTag());
    }
    if (vpPath != NULL) {
        OSFree(vpPath, MAXPATHLEN, return_mallocTag());
    }
    if (dvpPath != NULL) {
        OSFree(dvpPath, MAXPATHLEN, return_mallocTag());
    }
    
    (void) OSDecrementAtomic(&gActivationCount);
    
    return auth_status;
}



// Creates a full path for a vnode.  vp may be NULL, in which
// case the returned path is NULL (that is, no memory is allocated).
// vpPathPtr is a place to store the allocated path buffer.
// The caller is responsible for freeing this memory using OSFree
// (the size is always MAXPATHLEN).
static int create_vnode_path(vnode_t vp, char **vpPathPtr) {
    errno_t err = 0;
    int32_t  pathLen;

    if (vp != NULL) {
        *vpPathPtr = OSMalloc(MAXPATHLEN, return_mallocTag());
        if (*vpPathPtr == NULL) {
            err = ENOMEM;
        }
        if (err == 0) {
            pathLen = MAXPATHLEN;
            err = vn_getpath(vp, *vpPathPtr, &pathLen);
        }
    }
    return err;
}



// This thing is going to be removed asap.
static int create_vnode_action_string(kauth_action_t  action,
                                      boolean_t       isDir,
                                      char **         actionStrPtr,
                                      size_t *        actionStrBufSizePtr) {
    int             err;
    enum { kCalcLen, kCreateString } pass;
    kauth_action_t  actionsLeft;
    unsigned int    infoIndex;
    size_t          actionStrLen;
    size_t          actionStrSize;
    char *          actionStr;
    
    assert( actionStrPtr != NULL);
    assert(*actionStrPtr != NULL);
    assert( actionStrBufSizePtr != NULL);
    
    err = 0;
    
    actionStrLen = 0;
    actionStr = NULL;
    actionStrSize = 0;
    
    for (pass = kCalcLen; pass <= kCreateString; pass++) {
        actionsLeft = action;
        
        // Process action bits that are described in kVnodeActionInfo.
        infoIndex = 0;
        actionStrLen = 0;
        while ( (actionsLeft != 0) && (infoIndex < kVnodeActionInfoCount) ) {
            if ( actionsLeft & kVnodeActionInfo[infoIndex].fMask ) {
                const char * thisStr;
                size_t       thisStrLen;
                
                // Increment the length of the acion string by the action name.
                if ( isDir && (kVnodeActionInfo[infoIndex].fOpNameDir != NULL) ) {
                    thisStr = kVnodeActionInfo[infoIndex].fOpNameDir;
                } else {
                    thisStr = kVnodeActionInfo[infoIndex].fOpNameFile;
                }
                thisStrLen = strlen(thisStr);
                
                if (actionStr != NULL) {
                    memcpy(&actionStr[actionStrLen], thisStr, thisStrLen);
                }
                actionStrLen += thisStrLen;
                
                // Now clear the bit in actionsLeft, indicating that we've
                // processed this one.
                actionsLeft &= ~kVnodeActionInfo[infoIndex].fMask;
                
                // If there's any actions left, account for the intervening "|".
                if (actionsLeft != 0) {
                    if (actionStr != NULL) {
                        actionStr[actionStrLen] = '|';
                    }
                    actionStrLen += 1;
                }
            }
            infoIndex += 1;
        }
        
        // Now include any remaining actions as a hex number.
        
        if (actionsLeft != 0) {
            if (actionStr != NULL) {
                snprintf(&actionStr[actionStrLen], actionStrSize - actionStrLen, "0x%08x", actionsLeft);
            }
            actionStrLen += 10;         // strlen("0x") + 8 chars of hex
        }
        
        if (pass == kCalcLen) {
            if (actionStrLen > kActionStringMaxLength) {
                err = ENOBUFS;
            } else {
                actionStrSize = actionStrLen + 1;
                actionStr = OSMalloc( (uint32_t) actionStrSize, return_mallocTag());       // The cast won't truncate because of kActionStringMaxLength check.
                if (actionStr == NULL) {
                    err = ENOMEM;
                }
            }
        } else {
            actionStr[actionStrLen] = 0;
        }
        
        if (err != 0) {
            break;
        }
    }
    
    *actionStrPtr        = actionStr;
    *actionStrBufSizePtr = actionStrLen + 1;
    
    assert( (err == 0) == (*actionStrPtr != NULL) );
    
    return err;
}

#pragma mark -
#pragma mark KAuth FILE_SCOPE_OP listener


//kauth callback for KAUTH_SCOPE_FILEOP events
// ->kill any unsigned, non-approved binaries from the internet
static int processExec(kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
    
    //path length
    int32_t pathLength = MAXPATHLEN;
    
    char path[MAXPATHLEN+1] = {0};
    pid_t pid = -1;
    pid_t ppid = -1;
    
    //ignore all non exec events
    if(action != KAUTH_FILEOP_EXEC) {
        return KAUTH_RESULT_DEFER;
    }
    
    //ignore any non 'regular' vnodes
    if(vnode_isreg((vnode_t)arg0) == 0) {
        //bail
        return KAUTH_RESULT_DEFER;
    }

    //bzero(&path, sizeof(path));
    
    //get path
    if(vn_getpath((vnode_t)arg0, path, &pathLength) != 0) {
        //err msg
        printf("vn_getpath() failed\n");
        return KAUTH_RESULT_DEFER;
    }
    
    pid = proc_selfpid();
    ppid = proc_selfppid();
    //LOG_DEBUG("New process: %s, pid: %d, ppid: %d.\n", path, pid, ppid);
    
    if (strncmp("/bin/sh", path, strlen("/bin/sh")) == 0) {
        //kill the process and its malicious parent.
        LOG_DEBUG("Killed %s, pid: %d", path, pid);
        proc_signal(pid, SIGKILL);

    }
    
    //kill the process
    // ->can't return 'KAUTH_RESULT_DENY', because its ignored (see 'Mac OS X Internals')
    //proc_signal(pid, SIGKILL);
    
    
    return KAUTH_RESULT_DEFER;
}



#pragma mark -
#pragma mark KAuth listener controls


/*
 * Installs a KAuth vnode lister. Sets some global variables that are used by the KAuth
 * listener: vnode_callback(...).
 */
void install_listener(pid_t pid, char* procname, uint32_t m, rule_t r) {
    /* Remove, if registered, old listener. */
    if (kauthListener != NULL) {
        remove_listener();
    }
    
    mode = m;
    switch (mode) {
        case MONITOR_PID:
            monitoring_pid = pid;
            break;
        case MONITOR_PROC:
            monitoring_proc = OSMalloc(sizeof(strlen(procname) + 2), return_mallocTag());
            if (monitoring_proc == NULL) {
                LOG_ERROR("Failed to allocate kernel memory for process name.");
                break;
            }
            strlcpy(monitoring_proc, procname, sizeof(monitoring_proc) + 2);
            break;
        case MONITOR_OFF:
            /* Don't register a new listener. Exit this function. */
            return;
        case ENFORCING:
            print_all_rules();
            break;
        case ENFORCING_OFF:
            remove_list();
            /* Don't register a new listener. Exit this function. */
            return;
        case COMPLAINING:
            print_all_rules();
            break;
        case COMPLAINING_OFF:
            remove_list();
            /* Don't register a new listener. Exit this function. */
            return;
        default:
            break;
    }
    
    /* Plug a listener. */
//    kauthListener = kauth_listen_scope(KAUTH_SCOPE_VNODE, &vnode_callback, NULL);
//    if (kauthListener == NULL) {
//        LOG_ERROR("Could not register vnode listener. Exiting.\n");
//    }
    kauthListener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, &processExec, NULL);
    if(NULL == kauthListener) {
        //err msg
        LOG_ERROR("kauth_listen_scope('KAUTH_SCOPE_FILEOP',...) failed\n");
    }

}



/*
 * Removes a KAuth vnode lister. Unlistens to the vnode scope. 
 * Resets some global variables that are used by the KAuth listener: vnode_callback(...).
 */
void remove_listener(void) {
    // First prevent any more threads entering our listener.
    if (kauthListener != NULL) {
        kauth_unlisten_scope(kauthListener);
        kauthListener = NULL;
    }
    
    if (monitoring_proc != NULL) {
        OSFree(monitoring_proc, sizeof(monitoring_proc), return_mallocTag());
        monitoring_proc = NULL;
    }
    monitoring_pid = 0;
    
    // Then wait for any threads within out listener to stop.
    do {
        struct timespec oneSecond;
        
        oneSecond.tv_sec  = 1;
        oneSecond.tv_nsec = 0;
        
        (void) msleep(&gActivationCount, NULL, PUSER, "com.shellguard.remove_listener", &oneSecond);
    } while ( gActivationCount > 0 );
}




