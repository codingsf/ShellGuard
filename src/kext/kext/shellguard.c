
#include "definitions.h"
#include "shared_data.h"
#include "shellguard.h"
#include "kext_control.h"
#include "mac_hooks.h"
#include "filter.h"

#include <IOKit/IOLib.h>




kern_return_t shellguard_start(kmod_info_t *ki, void *d);
kern_return_t shellguard_stop(kmod_info_t *ki, void *d);


static OSMallocTag gMallocTag = NULL;

extern pid_t client_pid;

#pragma mark -
#pragma mark KEXT control functions

kern_return_t shellguard_start(kmod_info_t * ki, void *d)
{
    kern_return_t status = KERN_SUCCESS;
    gMallocTag = NULL;
    LOG_INFO("Hi kernel, ShellGuard is here to protect you! : )");
    
    install_kext_control();
    
    gMallocTag = OSMalloc_Tagalloc("com.shellguard.memtag", OSMT_DEFAULT);
    if (gMallocTag == NULL) {
        status = KERN_FAILURE;
    }
    init_list_structs();
    
    register_mac_policy(d);
    
    return status;
}

kern_return_t shellguard_stop(kmod_info_t *ki, void *d)
{
    uint32_t i = 5;
    while (client_connected()) {
        LOG_ERROR("Cannot unload kernel extension. Client still connected, but no worries, we'll kill it right now.");
        /* Stop the client. */
        proc_signal(client_pid, SIGINT);
        IOSleep(300);
        /* After 5 trials to stop the client gracefully, we forcefully kill it. */
        if (i == 0) {
            proc_signal(client_pid, SIGKILL);
        }
        i--;
    }
    
    unregister_mac_policy(d);
    
    remove_list_structs();
    
    if (gMallocTag != NULL) {
        OSMalloc_Tagfree(gMallocTag);
        gMallocTag = NULL;
    }
    remove_kext_control();

    LOG_INFO("We're outta here!\n");
    return KERN_SUCCESS;
}

OSMallocTag return_mallocTag(void) { return gMallocTag; }



