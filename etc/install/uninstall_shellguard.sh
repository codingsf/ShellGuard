#! /bin/bash

declare -i steps=5


echo "\n\t======ShellGuard uninstaller======\n"
if [ "$EUID" -ne 0 ]
  then echo "[-] Please run me as root (sudo sh uninstall_shellguard.sh)\n"
  exit
fi

echo "[+] (1/$steps) Killing ShellGuard daemon..."
killall ShellGuard

echo "[+] (2/$steps) Removing ShellGuard daemon..."
rm -rf /Applications/ShellGuard.app

echo "[+] (3/$steps) Unloading ShellGuard from kernel..." 
kextunload /Library/Extensions/ShellGuard.kext

echo "[+] (4/$steps) Removing ShellGuard from /System/Library/Extensions..."
rm -rf /Library/Extensions/ShellGuard.kext

echo "[+] (5/$steps) Removing LaunchDaemons..."
rm -rf /Library/LaunchDaemons/com.vivami.shellguard.daemon.plist
rm -rf /Library/LaunchDaemons/com.vivami.shellguard.kext.plist

echo "[+] Succesfully removed ShellGuard from your system.\n"