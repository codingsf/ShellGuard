
#ifndef definitions_h
#define definitions_h

#include <libkern/libkern.h>
#include <sys/kauth.h>
#include <mach/mach_types.h>
#include <sys/types.h>
#include <stdint.h>

struct VnodeActionInfo {
    kauth_action_t      fMask;                  // only one bit should be set
    const char *        fOpNameFile;            // descriptive name of the bit for files
    const char *        fOpNameDir;             // descriptive name of the bit for directories
    // NULL implies equivalent to fOpNameFile
};
typedef struct VnodeActionInfo VnodeActionInfo;


#define VNODE_ACTION(action)                        { KAUTH_VNODE_ ## action,     #action,     NULL       }
#define VNODE_ACTION_FILEDIR(actionFile, actionDir) { KAUTH_VNODE_ ## actionFile, #actionFile, #actionDir }

static const VnodeActionInfo kVnodeActionInfo[] = {
    VNODE_ACTION_FILEDIR(READ_DATA,   LIST_DIRECTORY),
    VNODE_ACTION_FILEDIR(WRITE_DATA,  ADD_FILE),
    VNODE_ACTION_FILEDIR(EXECUTE,     SEARCH),
    VNODE_ACTION(DELETE),
    VNODE_ACTION_FILEDIR(APPEND_DATA, ADD_SUBDIRECTORY),
    VNODE_ACTION(DELETE_CHILD),
    VNODE_ACTION(READ_ATTRIBUTES),
    VNODE_ACTION(WRITE_ATTRIBUTES),
    VNODE_ACTION(READ_EXTATTRIBUTES),
    VNODE_ACTION(WRITE_EXTATTRIBUTES),
    VNODE_ACTION(READ_SECURITY),
    VNODE_ACTION(WRITE_SECURITY),
    VNODE_ACTION(TAKE_OWNERSHIP),
    VNODE_ACTION(SYNCHRONIZE),
    VNODE_ACTION(LINKTARGET),
    VNODE_ACTION(CHECKIMMUTABLE),
    VNODE_ACTION(ACCESS),
    VNODE_ACTION(NOIMMUTABLE)
};


#define kVnodeActionInfoCount (sizeof(kVnodeActionInfo) / sizeof(*kVnodeActionInfo))


#if DEBUG
#define LOG_DEBUG(fmt, ...) printf("[SHELLGUARD DEBUG] " fmt "\n", ## __VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while (0)
#endif

#define LOG_MSG(...) printf(__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[SHELLGUARD ERROR] " fmt "\n", ## __VA_ARGS__)
#define LOG_INFO(fmt, ...) printf("[SHELLGUARD INFO] " fmt "\n", ## __VA_ARGS__)

#endif /* definitions_h */
