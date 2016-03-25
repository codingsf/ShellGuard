<img src="http://cl.ly/fSwN/logo_large.png" width="400">

Security is all about layers. ShellGuard aims to provide an extra generic layer of security by guarding the execution of a shell process. Research shows that OS X malware is strongly dependent on a shell process to harm the system. ShellGuard prevents the execution of shells by unknown processes.

ShellGuard is written in Swift :smile: and C :smiling_imp:.


## ShellGuard structure
ShellGuard consists of a kernel extension and a userspace client that communicate through a `PF_SYSTEM` socket. The kext uses OS X's TrustedBSD framework to hook the execution system calls and notified of process executions. Based on the policies defined in the `SG_config.json` file, the ShellGuard allows or denies the execution of the shell.

The ShellGuard daemon/client that remains in userspace and runs in privileged mode, which is why I have chosen to write it in Swift, a memory safe language. The daemon parses the ShellGuard policy file (JSON) and passes these rules to the kernel extension.


## Usage
ShellGuard consits of 2 parts: shellguard.kext, ShellGuardDaemon.app.

ShellGuard modes:
- `COMPLAIN`: Applies policies, but does _not_ enforce them. The daemon notifies the user when a policy is overriden and logs the action. In this mode, ShellGuard _is not_ protective.
- `ENFORCE`: Applies policies, and enforces them. The daemon notifies the user when a policy is enforced and logs the action. In this mode, ShellGuard _is_ protective and _blocks malware_.


## Installation

#### Disable SIP (partly!)
Because we have not been able yet to obtain a kext signing cert, by default OS X will not allow us to load the ShellGuard kext. We have to enable `kext-dev-mode` for it to allow unsigned kext loading.

- Go to Terminal.app
- Type: `sudo nvram boot-args="debug=0x146 kext-dev-mode=1 keepsyms=1"`

This enables `kext-dev-mode` and also enables symbolic links to ensure that crash logs are somewhat useful.

Iff you are running OSX 10.11 (El Capitan), you will have to __partly__ disable System Integerty Protection (SIP):
- Restart your Mac
- Press `CMD + R` right after your Mac starts to boot up and shows the Apple logo
- Your Mac will reboot into Recovery mode
- Go to Utilities in the top menu bar and go to Terminal
- Type: `csrutil enable --without-kext`
- Type: `reboot`

This will keep SIP intact, but only allow unsigned kext to be loaded. Note that, in order to load malicious kexts, the attacker has to be
root, so your system is compromised anyway.


## Author
[@_vivami](https://twitter.com/_vivami)

## License
Currently the project holds a [GPLv3 license](http://choosealicense.com/licenses/gpl-3.0/). I may loosen this up in the future to an MIT license.

