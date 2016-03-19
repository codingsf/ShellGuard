<img src="http://cl.ly/fSwN/logo_large.png" width="100">

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


## Author
[@_vivami](https://twitter.com/_vivami)

## License
Currently the project holds a [GPLv3 license](http://choosealicense.com/licenses/gpl-3.0/). I may loosen this up in the future to an MIT license.

