#ifndef shared_data_h
#define shared_data_h

#import <stdint.h>
#import <sys/proc.h>

#define BUNDLE_ID   "com.vivami.osx-shellguard"
#define AUTH_CODE   "Znkc/4N2GLmHoBkG[Ngg^8)xp&g4.NDsXV227b[c@9=43@Pthr"


#define MONITOR_PID     1
#define MONITOR_PROC    2
#define MONITOR_OFF     3
#define ENFORCING       4
#define ENFORCING_OFF   5
#define LOAD_RULES      6
#define COMPLAINING     7
#define COMPLAINING_OFF 8

#define READ_DATA		2
#define WRITE_DATA		4
#define EXECUTE         8


typedef struct {
    char        procname[256];
    char        kauth_operation[256];
    int32_t     kauth_op;
    char        path[1024];
    uint32_t    allow_root;
    uint32_t    path_wildcard;
    uint32_t    kauth_action;
} rule_t;


typedef struct  {
    char        credentals[64];
    pid_t       pid;
    char        procname[256];
    rule_t      rule;
} userspace_control_message;

typedef struct {
    uint32_t    mode;
    char        message[1024];
} kern_space_info_message;


#endif /* shared_data_h */