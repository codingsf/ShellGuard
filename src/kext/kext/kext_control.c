
#include "shellguard.h"
#include "kext_control.h"
#include "definitions.h"
#include "shared_data.h"
#include "mac_hooks.h"
#include "filter.h"

#include <sys/kern_control.h>
#include <sys/errno.h>
#include <sys/errno.h>

extern int32_t state;

/* local prototypes */
static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);


/* some globals */
static const char VALID_CLIENT_PATH[]   = "/Applications/ShellGuard/Contents/MacOS/ShellGuard";
static int32_t g_number_of_clients;
static kern_ctl_ref g_ctl_ref;
static u_int32_t g_client_unit          = 0;
static kern_ctl_ref g_client_ctl_ref    = NULL;
static boolean_t g_kern_ctl_registered  = FALSE;
pid_t client_pid;

static struct kern_ctl_reg g_ctl_reg = {
    BUNDLE_ID,            /* use a reverse dns name which includes a name unique to your comany */
    0,				   	  /* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
    0,					  /* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
    0,                    /* no privileged access required to access this filter */
    0,					  /* use default send size buffer */
    0,                    /* Override receive buffer size */
    ctl_connect,		  /* Called when a connection request is accepted */
    ctl_disconnect,		  /* called when a connection becomes disconnected */
    NULL,				  /* ctl_send_func - handles data sent from the client to kernel control - not implemented */
    ctl_set,			  /* called when the user process makes the setsockopt call */
    NULL			 	  /* called when the user process makes the getsockopt call */
};

#pragma mark -
#pragma mark User to Kernelspace comms

/*
 * Register kernel controls.
 */
kern_return_t install_kext_control(void)
{
    errno_t err = 0;
    // register the kernel control
    err = ctl_register(&g_ctl_reg, &g_ctl_ref);
    if (err == 0) {
        g_kern_ctl_registered = TRUE;
        LOG_INFO("ShellGuard kext control installed successfully!");
        return KERN_SUCCESS;
    } else {
        LOG_ERROR("Failed to install ShellGuard kext control!");
        return KERN_FAILURE;
    }
}

/*
 * Remove kernel controls.
 */
kern_return_t remove_kext_control(void)
{
    errno_t err = 0;
    // remove kernel control
    err = ctl_deregister(g_ctl_ref);
    switch (err) {
        case 0:
            LOG_INFO("Succesfully removed kext control");
            return KERN_SUCCESS;
        case EINVAL:
            LOG_ERROR("The kext control reference is invalid.");
            return KERN_FAILURE;
        case EBUSY:
            LOG_ERROR("The kext control still has clients attached. Please disconnect them first!");
            return KERN_FAILURE;
        default:
            return KERN_FAILURE;
    }
}


/*
 * Called when a client connects to the socket.
 * Auhtenticates the process that is trying to connect and stores some info for later use.
 */
static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
    /* we only accept a single client */
    if (client_connected() > 0) {
        return EBUSY;
    }
    
    /* Authenticate client. We don't want malicious clients connecting. We validate that the client process
     * path (its binary) is equal to VALID_CLIENT_PATH.
     */
    client_pid = proc_selfpid();
    char clientname[MAXPATHLEN] = {0};
    char clientpath[MAXPATHLEN] = {0};
    proc_selfname(clientname, MAXPATHLEN);
    if (get_process_path(client_pid, clientpath) != 0) {
        LOG_ERROR("Cannot validate path of the client process: %d: %s.\n This is fatal.", client_pid, clientname);
        return EBUSY;
    }
//  !! Turn this on in actual production mode !!
//    if (strncmp(clientpath, VALID_CLIENT_PATH, MAXPATHLEN) != 0) {
//        /* Malicious client is trying to connect. Reject & kill... */
//        proc_signal(client_pid, SIGKILL);
//        return EBUSY;
//    }
    LOG_INFO("Process %s with pid %d is authenticated.", clientname, client_pid);
    
    g_number_of_clients++;
    g_client_unit = sac->sc_unit;
    g_client_ctl_ref = ctl_ref;
    LOG_INFO("Client connected!");
    return 0;
}

/*
 * Called when the client disconnects.
 */
static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
    // reset some vars
    g_number_of_clients = 0;
    g_client_unit = 0;
    g_client_ctl_ref = NULL;
    LOG_INFO("Client with pid %d is disconnected!", client_pid);
    client_pid = 0;
    return 0;
}

/*
 * Receive data from userland to kernel.
 * This is where the state of the kext (sent from the client) is decided and 
 * proper params are set.
 */
static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
    int err = 0;
    if (len == 0 || data == NULL) {
        LOG_ERROR("Invalid data to command.");
        return EINVAL;
    }
    userspace_control_message* ucm = (userspace_control_message*) data;
    // lame authentication...
    if (strcmp(ucm->credentals, AUTH_CODE) != 0) {
        LOG_DEBUG("Authentication failed: %s", ucm->credentals);
        return EINVAL;
    }
    
    switch (opt) {
        case LOAD_WHITELIST:
            LOG_DEBUG("Received request to LOAD WHITELIST.");
            insert_whitelist_entry(&ucm->entry);
            break;
        case LOAD_SHELLS:
            LOG_DEBUG("Received request to LOAD SHELLS.");
            insert_shell_entry(&ucm->entry);
            break;
        case RESET_LISTS:
            LOG_DEBUG("Received request to enable RESET_LISTS mode.");
            remove_shells_list();
            remove_white_list();
            break;
        case ENFORCING:
            LOG_DEBUG("Received request to enable ENFORCING mode.");
            state = ENFORCING;
            break;
        case ENFORCING_OFF:
            LOG_DEBUG("Received request to disable ENFORCING mode.");
            state = ENFORCING_OFF;
            break;
        case COMPLAINING:
            LOG_DEBUG("Received request to enable COMPLAINING mode.");
            state = COMPLAINING;
            break;
        case COMPLAINING_OFF:
            LOG_DEBUG("Received request to disable COMPLAINING mode.");
            state = COMPLAINING_OFF;
            break;
        default:
            err = ENOTSUP;
            break;
    }
    return err;
}


/* 
 * return whether a client is connected.
 * @g_number_of_clients can only be 0 or 1.
 */
int32_t client_connected(void) {
    return g_number_of_clients;
}


#pragma mark -
#pragma mark Kernel to Userspace comms

/*
 * queue data so userland can read
 * this is used for the events when userland is already connected
 */
kern_return_t queue_userland_data(kern_space_info_message *kern_info_m)
{
    errno_t error = 0;
    if (g_client_ctl_ref == NULL) {
        LOG_ERROR("No client reference available.");
        return KERN_FAILURE;
    }
    error = ctl_enqueuedata(g_client_ctl_ref, g_client_unit, kern_info_m, sizeof(kern_space_info_message), CTL_DATA_EOR);
    if (error) {
        LOG_ERROR("ctl_enqueuedata error: %d", error);
    }
    return error;
}

