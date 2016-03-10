
#ifndef driver_control_h
#define driver_control_h

#include "rules.h"
#include <mach/mach_types.h>
#include <sys/types.h>


int32_t client_connected(void);
kern_return_t install_kext_control(void);
kern_return_t remove_kext_control(void);
kern_return_t queue_userland_data(kern_space_info_message *kern_info_m);

#endif
