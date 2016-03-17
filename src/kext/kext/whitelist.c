
#include "shellguard.h"
#include "whitelist.h"
#include "definitions.h"

int32_t             state;
static lck_mtx_t*   whitelist_lock = NULL;
static lck_mtx_t*   shelllist_lock = NULL;
white_list_t*       whitelist       = NULL;
shell_list_t*       shells          = NULL;

int32_t check_duplicate(white_entry *r);
int32_t check_duplicate_shell(white_entry *r);

#pragma -
#pragma mark List Operations

/*
 * Initializes first entry of the lists. This list is used to store all the blacklisted shells as well as
 * the whitelisted processes for ShellGuard. The list is looped through on *every* process exec.
 */
kern_return_t init_list_structs() {
    if (return_mallocTag() == NULL) {
        LOG_ERROR("Error while allocating memory for list structure. AllocTag is NULL.");
        return KERN_FAILURE;
    }
    whitelist = OSMalloc(sizeof(white_list_t), return_mallocTag());
    shells = OSMalloc(sizeof(shell_list_t), return_mallocTag());
    if ((whitelist == NULL) || (shells == NULL)) {
        LOG_ERROR("Error while allocating memory for list structures. Not enough memory.");
        return KERN_FAILURE;
    }
    
    lck_grp_attr_t*	grp_attrib = NULL;
    lck_attr_t*		lck_attrb  = NULL;
    lck_grp_t*		lck_group  = NULL;
    
    grp_attrib = lck_grp_attr_alloc_init();
    lck_group = lck_grp_alloc_init("mbuf_tag_allocate_id", grp_attrib);
    lck_grp_attr_free(grp_attrib);
    lck_attrb = lck_attr_alloc_init();
    
    whitelist_lock = lck_mtx_alloc_init(lck_group, lck_attrb);
    shelllist_lock = lck_mtx_alloc_init(lck_group, lck_attrb);
    
    lck_grp_free(lck_group);
    lck_attr_free(lck_attrb);
    
    LIST_INIT(whitelist);
    LIST_INIT(shells);
    return KERN_SUCCESS;
}


/*
 * Inserts a shell into the list of blacklisted shells.
 */
kern_return_t insert_shell_entry(white_entry *e) {
    
    lck_mtx_lock(shelllist_lock);
    
    if (check_duplicate_shell(e)) {
        LOG_DEBUG("Received duplicate shell: %s,", e->shell);
        lck_mtx_unlock(shelllist_lock);
        return KERN_ALREADY_IN_SET;
    }
    shell_entry_t* new_entry = OSMalloc(sizeof(shell_entry_t), return_mallocTag());
    if (new_entry == NULL) {
        LOG_ERROR("Error while allocating memory for shell structure. Not enough memory.");
        lck_mtx_unlock(shelllist_lock);
        return KERN_FAILURE;
    }
    memset(new_entry, 0, sizeof(white_entry_t));
    // this data should be treated as untrusted. More checks needed...
    if (e->shell[0] != 0){
        strlcpy(new_entry->shell, e->shell, MAXPATHLEN);
        LOG_DEBUG("Received black listed shell: %s", new_entry->shell);
        LIST_INSERT_HEAD(shells, new_entry, entries);
    } else {
        LOG_DEBUG("Received incomplete blacklisted shell: %s. Ignoring.", e->shell);
    }
    lck_mtx_unlock(shelllist_lock);
    return KERN_SUCCESS;
}


/*
 * Inserts a entry into the whitelist.
 */
kern_return_t insert_whitelist_entry(white_entry *e) {
    
    lck_mtx_lock(whitelist_lock);
    
    if (check_duplicate(e)) {
        LOG_DEBUG("Received deplicate entry: %s, %s", e->procname, e->shell);
        lck_mtx_unlock(whitelist_lock);
        return KERN_ALREADY_IN_SET;
    }
    white_entry_t* new_entry = OSMalloc(sizeof(white_entry_t), return_mallocTag());
    if (new_entry == NULL) {
        LOG_ERROR("Error while allocating memory for whitelist entry. Not enough memory.");
        lck_mtx_unlock(whitelist_lock);
        return KERN_FAILURE;
    }
    memset(new_entry, 0, sizeof(white_entry_t));
    // this data should be treated as untrusted. More checks needed...
    if ((e->procname[0] != 0) &&
        (e->shell[0]    != 0) ){
        strlcpy(new_entry->procname, e->procname, MAXPATHLEN);
        strlcpy(new_entry->shell, e->shell, MAXPATHLEN);
        
        LOG_DEBUG("Received whitelist entry: %s, %s", new_entry->procname, new_entry->shell);
        LIST_INSERT_HEAD(whitelist, new_entry, entries);
    } else {
        LOG_DEBUG("Received incomplete whitelist entry %s, %s. Ignoring.", e->procname, e->shell);
    }
    lck_mtx_unlock(whitelist_lock);
    return KERN_SUCCESS;
}

/*
 * Remove the first entry of the lists, initialized in init_list_structs().
 */
kern_return_t remove_list_structs(void) {
    lck_mtx_lock(whitelist_lock);
    remove_white_list();
    lck_mtx_unlock(whitelist_lock);
    
    lck_mtx_lock(shelllist_lock);
    remove_shells_list();
    lck_mtx_unlock(shelllist_lock);
    return KERN_SUCCESS;
}


/*
 * Remove all the entries in the list.
 * Called under mutex lock.
 */
void remove_white_list(void) {
    while(!LIST_EMPTY(whitelist)) {
        white_entry_t *new_entry = LIST_FIRST(whitelist);
        LOG_DEBUG("Deleting entry: %s, %s", new_entry->procname, new_entry->shell);
        LIST_REMOVE(new_entry, entries);
        OSFree(new_entry, sizeof(white_entry_t), return_mallocTag());
    }
}

/*
 * Remove all the entries in the list.
 * Called under mutex lock.
 */
void remove_shells_list(void) {
    while(!LIST_EMPTY(shells)) {
        shell_entry_t *entry = LIST_FIRST(shells);
        LOG_DEBUG("Deleting shell: %s", entry->shell);
        LIST_REMOVE(entry, entries);
        OSFree(entry, sizeof(shell_entry_t), return_mallocTag());
    }
    
}

/*
 * Checks whether the entry to be imported already exists in the list to prevent duplicates.
 * Return TRUE iff there is already a same entry in the list.
 * This function is called under mutex lock.
 */
int32_t check_duplicate(white_entry *r) {
    white_entry_t *rn;
    for (rn = LIST_FIRST(whitelist); rn != NULL; rn = LIST_NEXT(rn, entries)) {
        // strmcp is safe here: both rn and r contain '\0' since they are all copied using strlcpy
        if ((strcmp(rn->procname, r->procname) == 0) &&
            (strcmp(rn->shell, r->shell)       == 0) ) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Checks whether the entry to be imported already exists in the list to prevent duplicates.
 * Return TRUE iff there is already a same shell in the list.
 * This function is called under mutex lock.
 */
int32_t check_duplicate_shell(white_entry *r) {
    shell_entry_t *sn;
    for (sn = LIST_FIRST(shells); sn != NULL; sn = LIST_NEXT(sn, entries)) {
        // strmcp is safe here: both rn and r contain '\0' since they are all copied using strlcpy
        if (strcmp(sn->shell, r->shell) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}


#pragma -
#pragma mark Filters

/*
 * Heart of ShellGuard.
 */
uint32_t filter(char* proc, char* path) {
    uint32_t action = DENY;
    white_entry_t *rn;
    
    lck_mtx_lock(whitelist_lock);
    /* Loop thru all the whitelist */
    for (rn = LIST_FIRST(whitelist); rn != NULL; rn = LIST_NEXT(rn, entries)) {
        /* Check if there is a match with entries in the whitelist. Both are '\0' terminated.
         * For some very odd reason strncmp cause kernel panic here, seemingly overwriting other
         * processes memory. 
         */
        if ((strncmp(rn->procname, proc, MAXPATHLEN) == 0)       &&
            (strncmp(rn->shell,    path, MAXPATHLEN) == 0)       ) {
            /* there is a match, so allow the exec of the shell. */
            LOG_DEBUG("%s by %s is whitelisted.", path, proc);
            action = ALLOW;
        }
    }
    lck_mtx_unlock(whitelist_lock);
    return action;
}


/*
 * Checks if the shell is in the list of blocked shells. Returns TRUE iff it is blocked.
 */
uint32_t is_shell_blocked(const char* path) {
    shell_entry_t *sn;
    lck_mtx_lock(shelllist_lock);
    for (sn = LIST_FIRST(shells); sn != NULL; sn = LIST_NEXT(sn, entries)) {
        if (strncmp(sn->shell, path, MAXPATHLEN) == 0) {
            LOG_DEBUG("Shell %s is blacklisted.", path);
            lck_mtx_unlock(shelllist_lock);
            return TRUE;
        }
    }
    lck_mtx_unlock(shelllist_lock);
    return FALSE;
}





