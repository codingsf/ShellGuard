
#include "shellguard.h"
#include "rules.h"
#include "definitions.h"
#include "string_ops.h"

list_t* rules = NULL;
int32_t checkDuplicate(rule_t *r);

/*
 * Initializes first node of the Rules list. This list is used to store all the rules
 * that ShellGuard enforces. The list is looped through on *every* KAuth operation.
 */
kern_return_t init_rules_struct() {
    if (return_mallocTag() == NULL) {
        LOG_ERROR("Error while allocating memory for rules structure. AllocTag is NULL.");
        return KERN_FAILURE;
    }
    rules = OSMalloc(sizeof(list_t), return_mallocTag());
    if (rules == NULL) {
        LOG_ERROR("Error while allocating memory for rules structure. Not enough memory.");
        return KERN_FAILURE;
    }
    LIST_INIT(rules);
    return KERN_SUCCESS;
}


/*
 * Inserts a rule_t/node/rule into the list of rules.
 */
kern_return_t insert_rulenode(rule_t *r) {
    if (checkDuplicate(r)) {
        return KERN_ALREADY_IN_SET;
    }
    rule_node_t* r_node = OSMalloc(sizeof(rule_node_t), return_mallocTag());
    if (r_node == NULL) {
        LOG_ERROR("Error while allocating memory for rules structure. Not enough memory.");
        return KERN_FAILURE;
    }
    memset(r_node, 0, sizeof(rule_node_t));
    // this data should be treated as untrusted. More check needed...
    if ((r->procname[0]         != 0)  &&
        (r->kauth_operation[0]  != 0)  &&
        (r->path[0]             != 0)   ){
        strlcpy(r_node->procname, r->procname, sizeof(r_node->procname));
        strlcpy(r_node->kauth_operation, r->kauth_operation, sizeof(r_node->kauth_operation));
        strlcpy(r_node->path, r->path, sizeof(r_node->path));
        r_node->allow_root = r->allow_root;
        r_node->path_wildcard = r->path_wildcard;
        r_node->kauth_action = r->kauth_action;
        r_node->kauth_op = r->kauth_op;
        LOG_DEBUG("Received rule: %s, %s, %d, %s, %u, %d, %d", r_node->procname, r_node->kauth_operation, r_node->kauth_op, r_node->path, r_node->allow_root, r_node->path_wildcard, r_node->kauth_action);
        LIST_INSERT_HEAD(rules, r_node, pointers);
    } else {
        LOG_DEBUG("Received incomplete rule %s, %s, %s, %d, %d, %d. Ignoring.", r->procname, r->kauth_operation, r->path, r->allow_root, r->path_wildcard, r->kauth_action);
    }
    return KERN_SUCCESS;
}

/*
 * Remove the first node of the rules list, initialized in init_rules_struct()
 */
kern_return_t remove_rules_struct(void) {
    remove_list();
    if (rules != NULL) {
        OSFree(rules, sizeof(list_t), return_mallocTag());
    }
    return KERN_SUCCESS;
}


/*
 * Remove all the nodes/rules in the list.
 */
void remove_list(void) {
    while(!LIST_EMPTY(rules)) {
        rule_node_t *r_node = LIST_FIRST(rules);
        LOG_DEBUG("Deleting rule: %s, %s, %d, %s, %u, %d, %d", r_node->procname, r_node->kauth_operation, r_node->kauth_op, r_node->path, r_node->allow_root, r_node->path_wildcard, r_node->kauth_action);
        LIST_REMOVE(r_node, pointers);
        OSFree(r_node, sizeof(rule_node_t), return_mallocTag());
    }
}

/*
 * Checks whether the rule to be imported already exists in the list to prevent duplicates.
 */
int32_t checkDuplicate(rule_t *r) {
    rule_node_t *rn;
    int i = 0;
    for (rn = LIST_FIRST(rules); rn != NULL; rn = LIST_NEXT(rn, pointers)) {
        // strmcp is safe here: both rn and r contain '\0' since they are all copied using strlcpy
        if (strcmp(rn->procname, r->procname) != 0) {
            continue;
        }
        if (strcmp(rn->path, r->path) != 0) {
            continue;
        }
        if ((rn->kauth_op       == r->kauth_op      )   &&
            (rn->allow_root     == r->allow_root    )   &&
            (rn->path_wildcard  == r->path_wildcard )   &&
            (rn->kauth_action   == r->kauth_action  )   ) {
            LOG_INFO("Duplicate rule: %d, %s, %s, %d, %s, %u, %d, %d", i, rn->procname, rn->kauth_operation, rn->kauth_op, rn->path, rn->allow_root, rn->path_wildcard, rn->kauth_action);
            return TRUE;
        }
        i++;
    }
    return FALSE;
}


/*
 * Print all the rules in the list.
 */
void print_all_rules(void) {
    rule_node_t *rn;
    int i = 0;
    for (rn = LIST_FIRST(rules); rn != NULL; rn = LIST_NEXT(rn, pointers)) {
        LOG_DEBUG("Rule no.: %d, %s, %s, %d, %s, %u, %d, %d", i, rn->procname, rn->kauth_operation, rn->kauth_op, rn->path, rn->allow_root, rn->path_wildcard, rn->kauth_action);
        i++;
    }
}


/*
 * Compares the two strings (path) and checks if "needle" is in "stack", based on the wildcard operator. 
 * "/System/Library/" (stack) is in "/System/ *" (needle).
 */
int32_t path_match(const char* needle, const char* stack, int32_t wild) {
    if (wild) {
        return (strncmp(stack, needle, strlen(needle)) == 0) ? 1 : 0;
    } else {
        return (strncmp(stack, needle, strlen(stack)) == 0) ? 1 : 0;
    }
}

/* 
 * Heart of ShellGuard.
 * This currently is desgined in an "DENIED" on rule basis only. If no rule exist, it will just
 * allow the operation. If a DENY rule exist, it will enforce that DENY rule.
 */
int32_t filter(const char* proc, const char* kauth_operation, int32_t action, const char* path) {
    int32_t policy_for_process_exists = FALSE;
    rule_node_t *rn;
    /* Loop thru all the rules */
    for (rn = LIST_FIRST(rules); rn != NULL; rn = LIST_NEXT(rn, pointers)) {
        
        if (strncmp(rn->procname, proc, sizeof(rn->procname)) == 0) {
            /* there is a policy for the process */
            policy_for_process_exists = TRUE;
            if (((action & rn->kauth_op) == rn->kauth_op) && path_match(rn->path, path, rn->path_wildcard)) {
                    return rn->kauth_action;
            }
        }
    }
    /* if a policy exsists, but no matching action or path, the process is not allowed to
       do that call, so: deny the action */
    //return (policy_for_process_exists) ? 0 : 1;
    return TRUE;
}



void print_op(char* procname, int action, char* path, char* operation) {
    //LOG_DEBUG("action: %d", action);
    int res = action & WRITE_DATA;
    //LOG_DEBUG("res: %d\n", res);
    if (res == WRITE_DATA) {
        LOG_DEBUG("%s writing data: %s on %s\n", procname, operation, path);
    }
}






