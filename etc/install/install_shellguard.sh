#! /bin/bash

declare -i steps=5


echo "\n\t======ShellGuard installer======\n"
if [ "$EUID" -ne 0 ]
  then echo "[-] Please run me as root (sudo sh install_shellguard.sh)\n"
  exit
fi
echo "[+] (1/$steps) Installing ShellGuard kext to /Library/Extensions..."
cp -R ShellGuard.kext /Library/Extensions/
chmod -R 755 /Library/Extensions/ShellGuard.kext
chown -R root:wheel /Library/Extensions/ShellGuard.kext

echo "[+] (2/$steps) Installing ShellGuard Daemon to /Applications"
cp -R ShellGuard.app /Applications/ShellGuard.app
chown -R root:wheel /Applications/ShellGuard.app

echo "[+] (3/$steps) Creating LaunchDaemons..."
cp -R com.vivami.ShellGuard.kext.plist /Library/LaunchDaemons/com.vivami.ShellGuard.kext.plist
chmod -R 755 /Library/LaunchDaemons/com.vivami.ShellGuard.kext.plist
chown -R root:wheel /Library/LaunchDaemons/com.vivami.ShellGuard.kext.plist

cp -R com.vivami.ShellGuard.plist /Library/LaunchDaemons/com.vivami.ShellGuard.daemon.plist
chmod -R 755 /Library/LaunchDaemons/com.vivami.ShellGuard.daemon.plist
chown -R root:wheel /Library/LaunchDaemons/com.vivami.ShellGuard.daemon.plist

echo "[+] (4/$steps) Launching ShellGuard"
launchctl load -w /Library/LaunchDaemons/com.vivami.ShellGuard.daemon.plist
launchctl load -w /Library/LaunchDaemons/com.vivami.ShellGuard.kext.plist

echo "[+] (5/$steps) Cleaning kernel cache, may be necessary"
rm -R Extensions.kextcache
rm -R Extensions.mkext

echo "[+] Done. Maybe reboot? Check Console.app for SHELLGUARD messages."