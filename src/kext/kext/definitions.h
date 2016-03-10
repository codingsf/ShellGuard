
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

#define	SYS_exit           1
#define	SYS_fork           2
#define	SYS_read           3
#define	SYS_wait4          7
#define	SYS_ptrace         26
#define	SYS_recvmsg        27
#define	SYS_execve         59
#define	SYS_getxattr       234
#define	SYS_listxattr      240
#define	SYS_posix_spawn    244

// sysent definitions
// found in xnu/bsd/sys/sysent.h
typedef int32_t	sy_call_t(struct proc *, void *, int *);
typedef void	sy_munge_t(const void *, void *);


struct kernel_info
{
    mach_vm_address_t running_text_addr; // the address of running __TEXT segment
    mach_vm_address_t disk_text_addr;    // the same address at /mach_kernel in filesystem
    mach_vm_address_t kaslr_slide;       // the kernel aslr slide, computed as the difference between above's addresses
    void *linkedit_buf;                  // pointer to __LINKEDIT buffer containing symbols to solve
    uint64_t linkedit_fileoff;           // __LINKEDIT file offset so we can read
    uint64_t linkedit_size;
    uint32_t symboltable_fileoff;        // file offset to symbol table - used to position inside the __LINKEDIT buffer
    uint32_t symboltable_nr_symbols;
    uint32_t stringtable_fileoff;        // file offset to string table
    uint32_t stringtable_size;
    // other info from the header we might need
    uint64_t text_size;                  // size of __text section to disassemble
    struct mach_header_64 *mh;           // ptr to mach-o header of running kernel
    uint32_t fat_offset;                 // the file offset inside the fat archive for the active arch
};


/* for all versions before Mavericks, found in bsd/sys/sysent.h */
struct sysent {		/* system call table */
    int16_t		sy_narg;        /* number of args */
    int8_t		sy_resv;        /* reserved  */
    int8_t		sy_flags;       /* flags */
    sy_call_t	*sy_call;       /* implementing function */
    sy_munge_t	*sy_arg_munge32; /* system call arguments munger for 32-bit process */
    sy_munge_t	*sy_arg_munge64; /* system call arguments munger for 64-bit process */
    int32_t		sy_return_type; /* system call return types */
    uint16_t	sy_arg_bytes;	/* Total size of arguments in bytes for
                                 * 32-bit system calls
                                 */
};

/* Sysent structure got modified in Mavericks */
struct sysent_mavericks {
    sy_call_t   *sy_call;
    sy_munge_t  *sy_arg_munge32;
    sy_munge_t  *sy_arg_munge64;
    int32_t     sy_return_type;
    int16_t     sy_narg;
    uint16_t    sy_arg_bytes;
};

/* And again in Yosemite */
struct sysent_yosemite {
    sy_call_t   *sy_call;
    sy_munge_t  *sy_arg_munge64;
    int32_t     sy_return_type;
    int16_t     sy_narg;
    uint16_t    sy_arg_bytes;
};


#define DISABLE 0
#define ENABLE 1

#define MAVERICKS   13
#define YOSEMITE    14
#define EL_CAPITAN  15


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
