# POFR - Penguin OS Forensic (or Flight) Recorder

![GitHub Logo](/POFR.png)<br>

## Introduction
The Penguin OS Forensic (or Flight) Recorder (POFR) collects, stores and organizes for further analysis in a relational layer:
* process execution 
* file access 
* network/socket endpoint creation data 

from the Linux Operating System and derivatives. Like an aircraft flight recorder its main purpose is to reliably record all of these events from each of the monitored clients, so that IT experts (security analysts, system administrators, DevOps engineers and information security researchers) can then use the collected information to:
<br>
* Examine/interrelate in great detail processes, file access and network endpoint events in a monitored system in the exact order they occurred.<br>
* Detect computer account involvement misbehaving apps and/or malware. <br>
* Conduct post mortem evidence after security compromises with the evidence stowed away from the monitored system. <br>
* Conduct incident threat response exercises and study their effect on Linux systems. 
* Provide reliable log records for Linux systems that need to comply with the logging/auditing requirements of the PCI-DSS and HIPAA standards.
* Obtain and create your own threat and OSINT datasets from the collected data.
* Researchers can use this tool to create datasets from cybersecurity exercises and reliably observe what happens to system at OS level.

POFR uses an agentless client/server architecture. Clients are the systems to monitor and they push data to a server via the SSH protocol. The server parses the data and updates a Relational Database that is used to store and present the data for further analysis. The overall architecture was designed to provide:
<br>
* Absolute transparency on what's happening on the system (source code provided via an Open Source license. No proprietary binaries or blackboxes)
* Minimum implementation complexity: No proprietary kernel hooks or complex installation/deployment software dependencies. 
* Acceptable system security: No agents running on client systems exposing open network ports. Data are cryptographically signed and pushed to the server by using encrypted channels.
* Balanced computational overhead and data accuracy: The data extracted from the clients should provide a reasonable level of accuracy to reconstruct event sequences, not at the expense of computational overhead for the monitored systems.
  

POFR clients have been tested with CentOS/RHEL/ALMALinux versions 7 and 8, Fedora 32/33/34/35, as well as recent versions of Ubuntu.
For a server, we recommend either a CentOS 7 or a Fedora 33/34 distro OR the sample KVM and Docker images provided. 

## Dependencies and requirements

Minimal dependencies are required. A compatible distro. For the client part, the following Linux distributions are known to work with POFR:
* RHEL7/CentOS 7
* RHEL8/CentOS 8/AlmaLinux 8/Rocky Linux 8
* RHEL9/CentOS 9/AlmaLinux 9/Rocky Linux 9
* Fedora 33/34/35/36/37
* Ubuntu 18.04 LTS/20.04 LTS/22.04.1 LTS

For the server part, we recommend:
* Fedora 35/36 
* RHEL/AlmaLinux/Rocky Linux 9 

with a MariaDB (versions 10.5 and 10.6) RDBMS backend.

Everything else needed by the client and server components is provided by the POFR itself (including its own PERL distribution which is usually based on the most/recent up-to-date PERL version (v. 5.36.0)). 

In addition, you will need to ensure that: 
* The POFR clients can reach port 22 (SSH) of the POFR server (directly or via NAT)
* The IP address, FQDN and SSH keys of the POFR server need to remain the same throughout the monitoring session.
* For the server, one needs to ensure adequate disk space (say 1.5 Gb per client per hour), RAM (4 Gigs per client) and cpu cores (4-8 cores per client). 

For a more detailed overview of the installation process and technical operations, please consult the [POFR Technical Operations and User Manual](doc/POFRmanual.pdf). 

POFR distributes a copy of the IP2Location™ Lite, an open source geolocation database with limited GeoIP2 location accuracy. The copy receives monthly updates, as part of the POFR repo maintenance. However, all users can register for an individual license in https://lite.ip2location.com or they could adapt the code to use their commercial/paid versions for greater location accuracy.  

## License, Credits and Release Versions

POFR is an Open Source solution distributed under the terms of the GNU General Public License version 2. Please consult the [LICENSE file](/LICENSE) for more details. It is developed by Georgios Magklaras. 

The latest production release of POFR is v1.1.0 named "Lorinda Cherry" (Feb 27 2022). Previous versions are available from the [POFR Release Archive](https://github.com/gmagklaras/POFR/releases).  

The name of every POFR release honors the contribution of women in Computer Science and Mathematics.

The POFR logo was designed by [Heráclito López Bojórquez](https://www.imdb.com/name/nm3736848/).

The POFR project is sponsored by [Steelcyber Scientific](https://www.steelcyber.com). <br>

[IP2Location™ Lite](https://lite.ip2location.com/faq) is a registered trademark of the open source geolocation database.

