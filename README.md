## mkvenom.sh

:snake: `mkvenom.sh` is a Bash script which generates a selection of common Metasploit Framework `msfvenom` payloads for a specific target machine.

The idea is to kick this off in the background while performing initial scanning and enumeration of a target during a penetration test activity to speed up your testing workflow (see also: [ptboot](https://github.com/phraxoid/ptboot)). It's slow and it's imprecise, but in some circumstances it can be a good time saving tool.

![Screenshot](https://user-images.githubusercontent.com/29228695/36505369-2e74c050-174b-11e8-9d85-0f229dbf6e96.PNG)

## Features

This script will create commonly used Metasploit Framework payloads such as reverse meterpreter shells, bind shells etc., including 32-bit/64-bit and staged/inline variants.

It will produce a directory called `payloads` which will contain a library of ready to use payload files built using the local and remote TCP/IP parameters specified via the command line:

![Output](https://user-images.githubusercontent.com/29228695/36505371-2f76c39a-174b-11e8-88ab-4737e413091e.PNG)

## Requirements

The only requirements are the presence of Metasploit Framework 4.16+ and the Bash shell.

This script is intended for use in a Linux environment and has been tested on Kali Linux 2018.1. 

## Usage

Clone or download the `mkvenom.sh` file from this repository in to your Linux environment. You might want to consider placing it in `~/bin` or `/usr/local/bin`.

A directory called `payloads` will be created in the current working directory when the script runs.

Command line usage syntax:

```
Usage: mkvenom.sh <target-ip> <target-port> <local-ip> <local-port> [os]"
           <target-ip>   - Remote target's IP address."
           <target-port> - Remote target's port (e.g. for bind shells)."
           <local-ip>    - Local IP address (e.g. for reverse shell connections)."
           <local-port>  - Local port (e.g. a MSF multi/handler's listening port)."
           [os]          - Restrict payload generation to one operating system (optional)."
                            Valid values: linux, windows, osx, bsd or solaris."
```

For example, if the local penetration tester's system has an IP address of 192.168.10.200 and a remote Linux target system has an IP address of 10.20.20.1:

`./mkvenom.sh 10.20.20.1 4444 192.168.10.200 443 linux`

In the above example, payloads which bind to an address on the target would use port 4444 whilst payloads which make reverse connections back to the local machine would use port 443.

## License

This software is published here under the MIT licence.

## Disclaimer

This software is provided "as is" without any representations or warranties, express or implied.
