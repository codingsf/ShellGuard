
#ifndef kauth_controls_h
#define kauth_controls_h

#include "shared_data.h"

void install_listener(pid_t pid, char* procname, uint32_t m, rule_t r);
void remove_listener(void);


#endif /* kauth_controls_h */
