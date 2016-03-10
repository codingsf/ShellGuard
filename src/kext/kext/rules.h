
#ifndef rules_h
#define rules_h


#include "shared_data.h"

#include <sys/queue.h>
#include <sys/syslimits.h>
#include <libkern/libkern.h>
#include <sys/proc.h>

typedef struct rule_node_t {
    pid_t       pid;
    char        procname[NAME_MAX];
    char        kauth_operation[NAME_MAX];
    char        path[MAXPATHLEN];
    uint32_t    allow_root;
    uint32_t    path_wildcard;
    uint32_t    kauth_action;
    int32_t     kauth_op;
    LIST_ENTRY(rule_node_t) pointers;
} rule_node_t;


typedef LIST_HEAD(list, rule_node_t) list_t;

kern_return_t init_rules_struct(void);
kern_return_t remove_rules_struct(void);
kern_return_t insert_rulenode(rule_t *r);
void remove_list(void);
void print_all_rules(void);
int32_t filter(const char* proc, const char* kauth_operation, int32_t action, const char* path);


#endif /* rules_h */
