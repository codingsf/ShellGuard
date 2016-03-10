@import Foundation;
@import Darwin;

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#import <ShellGuardDaemon-Swift.h>
#import "ShellGuardDaemon-Bridging-Header.h"



/*
 * Gets the control ID that the kernel registers using the socket connection.
 */
UInt32 getControlIdentifier(int socket) {
    struct ctl_info ctl_info = {0};
	strlcpy(ctl_info.ctl_name, BUNDLE_ID, sizeof(ctl_info.ctl_name));
	if (ioctl(socket, CTLIOCGINFO, &ctl_info)) {
		printf("ioctl failed on kernel control socket: %s\n", strerror(errno));
		return 0;
	}
	return ctl_info.ctl_id;
}

/*
 * Initializes global dispatch queue used capture messages from kernelspace and handle them using the 
 * specified function.
 */
void init_dispatch_queues(int32_t socket) {
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
    ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socket, 0, queue);
    dispatch_source_set_event_handler(ds, ^{
        process_kernel_message(socket);
    });
    dispatch_resume(ds);
}

/*
 * Function that is called from the dispatch queue opon reception of a kernelspace message. This function receives
 * the actual message and passes it via Obj-C cast to Swift.
 */
void process_kernel_message(int32_t socket) {
    ssize_t bytes_read = 0;
    kern_space_info_message data = {0};
    bytes_read = recv(socket, &data, sizeof(kern_space_info_message), 0);
    if (bytes_read < 0) {
        printf("[ERROR] Receive error.");
    } else if (bytes_read < sizeof(kern_space_info_message)) {
        printf("[ERROR] Received smaller buffer than expected from kernel.");
    } else {
        // create obj-c string from C char array
        NSString* Obj_kernel_message = [NSString stringWithCString:data.message encoding:NSASCIIStringEncoding];
        int32_t mode = data.mode;
        // create Swift object containging the function to be called.
        SwiftHelper *instance = [[SwiftHelper alloc] init];
        // call swift function
        [instance receiveMessageFromKext: Obj_kernel_message mode: mode];
    }
}


/*
 * Creates a rule_t struct from Swift passed paramters. This function should be implemented in Swift
 * in the future.
 */
rule_t* toRuleStruct(const char* procname,
                     const char* kauth_operation,
                     uint32_t kauth_op,
                     const char* path,
                     bool root,
                     uint32_t path_wildcard,
                     uint32_t kauth_action) {
    rule_t* r = (rule_t*) malloc(sizeof(rule_t));
    if (r == NULL) {
        printf("[ERROR] Failed to allocate memory for rule.");
        printf("[ERROR] Skipping rule %s; %s; %s; %d; %d; %d.", procname, kauth_operation, path, root, path_wildcard, kauth_action);
    }
    bzero(r, sizeof(rule_t));
    strlcpy(r->procname, procname, sizeof(r->procname));
    strlcpy(r->kauth_operation, kauth_operation, sizeof(r->kauth_operation));
    strlcpy(r->path, path, sizeof(r->path));
    //strlcpy(r->allow_root, root, sizeof(r->allow_root));
    r->allow_root = root;
    r->path_wildcard = path_wildcard;
    r->kauth_action = kauth_action;
    r->kauth_op = kauth_op;
    return r;
}

/* Copies everything to a userspace_control_message struct and sends it to the kernel.
 * This function assumes that arguments are checked and safe.
 */
int32_t prepControlDataAndSend(int socket, UInt32 cmd, UInt32 pid, const char* procname, rule_t* r) {
    userspace_control_message ucm = {0};
    strlcpy(ucm.credentals, AUTH_CODE, sizeof(ucm.credentals));
    strlcpy(ucm.procname, procname, sizeof(ucm.procname));
    ucm.pid = pid;
    if (r != NULL)
        ucm.rule = *r;
    UInt32 retval = setsockopt(socket, SYSPROTO_CONTROL, cmd, &ucm, (socklen_t) sizeof(ucm));
    if (retval != 0) {
        printf("setsockopt error: %s, errno = %d\n", strerror(errno), errno);
    }
    // deallocating Rule struct from toRuleStruct(char*, char*, char*)
    if (r != NULL)
        free(r);
    return retval;
}



