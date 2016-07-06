#ifndef shared_data_h
#define shared_data_h

#import <stdint.h>
#import <sys/proc.h>

#define BUNDLE_ID   "com.vivami.osx-shellguard"
#define AUTH_CODE   "Znkc/4N2GLmHoBkG[Ngg^8)xp&g4.NDsXV227b[c@9=43@Pthr"


#define LOAD_WHITELIST  1
#define LOAD_SHELLS     2
#define RESET_LISTS     3
#define ENFORCING       4
#define ENFORCING_OFF   5

#define COMPLAINING     7
#define COMPLAINING_OFF 8

#define UNSIGNED        0


typedef struct {
    char    procname[MAXPATHLEN];
    char    shell[MAXPATHLEN];
} entry_t;


typedef struct  {
    char        credentals[64];
    entry_t     entry;
} userspace_control_message;

typedef struct {
    uint32_t    mode;
    uint32_t    signed_bin;
    uint32_t    pid;
    uint32_t    ppid;
    char        message[1024];
} kern_space_info_message;

#endif /* shared_data_h */
