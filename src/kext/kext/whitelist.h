
#ifndef rules_h
#define rules_h


#include "shared_data.h"

#include <sys/queue.h>
#include <libkern/libkern.h>

typedef struct white_entry_t {
    char        procname[MAXPATHLEN+1];
    char        shell[MAXPATHLEN+1];
    LIST_ENTRY(white_entry_t) entries;
} white_entry_t;

typedef struct shell_entry_t {
    char        shell[MAXPATHLEN+1];
    LIST_ENTRY(shell_entry_t) entries;
} shell_entry_t;

typedef LIST_HEAD(white_list, white_entry_t) white_list_t;
typedef LIST_HEAD(black_list, shell_entry_t)  shell_list_t;



kern_return_t init_list_structs(void);
kern_return_t remove_list_structs(void);
kern_return_t insert_whitelist_entry(white_entry *e);
kern_return_t insert_shell_entry(white_entry *e);
void remove_white_list(void);
void remove_shells_list(void);
uint32_t filter(char* proc, char* path);
uint32_t is_shell_blocked(const char* path);

#endif /* rules_h */
