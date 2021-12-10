# POFR - Penguin OS Forensic (or Flight) Recorder

![GitHub Logo](/POFR.png)<br>

## Introduction
The Penguin OS Flight Recorder collect, stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System and derivatives. Like an aircraft flight recorded (or black box), its main purpose is to **reliably reproduce/replay** OS level events that concern process execution, file access and network endpoint creation from each of the monitored Linux clients. IT experts (security analysts, system administrators, devops engineers and information security researchers) can then use the collected information to:
<br>
* Examine/interrelate in great detail processes, file access and network endpoint events in a monitored system.
* Detect computer account involvement misbehaving apps and/or malware. <br>
* Conduct post mortem evidence after security compromises with the evidence stowed away from the monitored system. <br>
* Conduct incident threat response exercises and see their effect on Linux systems. 
* Obtain threat and OSINT information from the collected data.

POFR uses a client/server architecture. Clients are the systems to monitor and they push data to a server via the SSH protocol. The server parses the data and updates a Relational Database that is used to store and present the data for further analysis. The overall architecture was designed to provide:
<br>
* Absolute transparency on what's happening on the system (source code provided via an Open Source license. No proprietary binaries or blackboxes)
* Minimum implementation complexity: No proprietary kernel hooks or complex installation/deployment software dependencies. 
* Acceptable system security: No agents running on client systems exposing open ports. Data are cryptographically signed and pushed to the server by using encrypted channels.
* Balanced computational overhead and data accuracy: The data extracted from the clients should provide a reasonable level of accuracy to reconstruct event sequences, not at the expense of computational overhead for the monitored systems.
  

POFR clients have been tested with CentOS/RHEL/ALMALinux versions 7 and 8, Fedora 32/33/34/35, as well as recent versions of Ubuntu.
For a server, we recommend either a CentOS 7 or a Fedora 33/34 distro OR the sample KVM and Docker images provided. 

## Dependencies and requirements

Minimal dependencies are required. A compatible distro. For the client part, the following Linux distributions are known to work with POFR:
* RHEL/CentOS 7
* RHEL/CentOS 8
* Fedora 34/35
* Ubuntu 18.04 LTS/20.04 LTS

For the server part, we recommend:
* Fedora 34/35 with MariaDB (10.4 and 10.5)

Everything else needed by the client and server components is provided. The only thing you need to ensure is that: 
* The POFR clients can reach port 22 (SSH) of the POFR server (directly or via NAT)
* The IP address, FQDN and SSH keys of the POFR server need to remain the same throughout the monitoring session.
* For the server, one needs to ensure adequate disk space (say 1.5 Gb per client per hour), RAM (4 Gigs per client) and cpu cores (4-8 cores per client). 

For a more detailed overview of the installation process and technical operations, please consult the [POFR Technical Operations and User Manual](doc/POFRmanual.pdf). 

## License and Credits

POFR is an Open Source solution distributed under the terms of the GNU General Public License version 2. Please consult the [LICENSE file](/LICENSE) for more details. It is developed by Georgios Magklaras. 

The POFR logo was designed by [Heráclito López Bojórquez](https://www.imdb.com/name/nm3736848/).

The POFR project is sponsored by [Steelcyber Scientific](https://www.steelcyber.com). <br>



