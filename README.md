![shellguard_logo](http://cl.ly/fN4F/shellguard_logo.png)

Security is all about layers. ShellGuard aims to provide an extra generic layer of security by guarding the execcution of a shell process. Research shows that OS X malware is dependend on a shell process. ShellGuard prevents the execution of shells by unknown processes.

ShellGuard is written in Swift :smile: and C :smiling_imp:.


## ShellGuard structure
ShellGuard consists of a kernel extension and a userspace client that communicate through a `PF_SYSTEM` socket. The kext uses [KAuth](https://developer.apple.com/library/mac/technotes/tn2127/_index.html)'s `vnode scope` listener to get notified of file system operations performed by applications. Based on the policies defined in the `policies.shellguard` file, the kernel allows or denies the file system operation.

The cagekeeper daemon/client that remains in userspace and runs in privileged mode, which is why I have chosen to write it in Swift, a memory safe language. The daemon parses the ShellGuard policy file (JSON) and passes these rules to the kernel extension.


## Usage
ShellGuard consits of 2 parts: shellguard.kext, ShellGuardDaemon.app.

ShellGuard modes:
- `COMPLAIN`: Applies policies, but does not enforce them. The daemon notifies the user when a policy is overriden and logs the action. In this mode, ShellGuard _is not_ protective.
- `ENFORCE`: Applies policies, and enforces them. The daemon notifies the user when a policy is enforced and logs the action. In this mode, ShellGuard _is not_ protective and _blocks malware_.


## Author
[@_vivami](https://twitter.com/_vivami)

## License
Currently the project holds a [GPLv3 license](http://choosealicense.com/licenses/gpl-3.0/). I may loosen this up in the future to an MIT license.
