# POFR - Penguin OS Forensic (or Flight) Recorder

![GitHub Logo](/POFR.png)<br>

## Introduction
The Penguin OS Flight Recorder collects process execution, file access and network/socket endpoint data from the Linux Operating System. Like an aircraft flight recorded (or black box), its main purpose is to **reliably reproduce/replay** OS level events that concern process execution, file access and network endpoint creation from each of the monitored Linux clients. IT experts (security analysts, system administrators, devops engineers can then use the collected information to:
<br>
* Examine/interrelate in great detail processes, file access and network endpoint events in a monitored system.
* Detect computer account involvement misbehaving apps and/or malware. <br>
* Conduct post mortem evidence after security compromises with the evidence stowed away from the monitored system. <br>
* Conduct incident threat response exercises and see their effect on Linux systems. 

POFR uses a client/server architecture. Clients are the systems to monitor and they push data to a server via the SSH protocol. The server parses the data and updates a Relational Database that is used to store and present the data for further analysis. Emphasis is given on minimizing the computational overhead and implementtation complexity of the monitoring process. No kernel modules, no agents exposing open network ports to obtain the data and no interference/reliance with system distro specific modules are required on the client systems. The idea is to easily install the POFR within minutes, register it to a server and start pushing data to the server. 

## Compatibility

POFR clients have been tested with CentOS/RHEL/ALMALinux versions 7 and 8, Fedora 32/33/34, as well as recent versions of Ubuntu.
For a server, we recommend either a CentOS 7 or a Fedora 33/34 distro OR the sample KVM and Docker images provided. 

## Dependencies and requirements

Minimal dependencies are required. A compatible distro (see section Compatibility). Everything needed by the client and server components is provided. The only thing you need to ensure is that: 
-the POFR clients can reach port 22 (SSH) of the POFR server (directly or via NAT)
-The IP address, FQDN and SSH keys of the POFR server need to remain the same throughout the monitoring session.
-For the server, one needs to ensure adequate disk space (say 1.5 Gb per client per hour), RAM (4 Gigs per client) and cpu cores (4-8 cores per client). 

For a more detailed overview of the installation process, please consult the INSTALL.txt document. 

## License and Credits

POFR is an Open Source solution sponsored by [Steelcyber Scientific](https://www.steelcyber.com). <br>



