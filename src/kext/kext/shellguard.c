
#include "definitions.h"
#include "shared_data.h"
#include "shellguard.h"
#include "kext_control.h"
#include "kauth_controls.h"

#include <IOKit/IOLib.h>




kern_return_t shellguard_start(kmod_info_t *ki, void *d);
kern_return_t shellguard_stop(kmod_info_t *ki, void *d);


static OSMallocTag gMallocTag = NULL;

#pragma mark -
#pragma mark KEXT control functions

kern_return_t shellguard_start(kmod_info_t * ki, void *d)
{
    kern_return_t status = KERN_SUCCESS;
    gMallocTag = NULL;
    LOG_INFO("Starting........\n");
    LOG_INFO("Installing cagekeeper kext controls...\n");
    install_kext_control();
    
    LOG_INFO("Initialzing some memory.");
    gMallocTag = OSMalloc_Tagalloc("com.shellguard.memtag", OSMT_DEFAULT);
    if (gMallocTag == NULL) {
        status = KERN_FAILURE;
    }
    init_rules_struct();

    return status;
}

kern_return_t shellguard_stop(kmod_info_t *ki, void *d)
{
    while (client_connected()) {
        LOG_ERROR("Cannot unload kernel extension. Client still connected.");
        // kill client? Waiting instead...
        IOSleep(5000);
    }
    LOG_INFO("Removing kauth listener.\n");
    remove_listener();
    
    LOG_INFO("Cleaning up memory.");
    remove_rules_struct();
    
    if (gMallocTag != NULL) {
        OSMalloc_Tagfree(gMallocTag);
        gMallocTag = NULL;
    }
    LOG_INFO("Removing kext control.\n");
    remove_kext_control();

    LOG_INFO("We're outta here!\n");
    return KERN_SUCCESS;
}

OSMallocTag return_mallocTag(void) { return gMallocTag; }



