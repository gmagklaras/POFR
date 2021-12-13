#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.34.0/x86_64-linux -I ../pofrperl/lib/5.34.0
#
use lib '../pofrperl/lib/site_perl/5.34.0';

#scannet.pl: This script parses /proc/net/tcp(6) and /proc/net/udp(6) files for network endpoint data.
#Started and stopped by the the POFR CLIENT startclient.pl and stopclient.pl scripts.
#(C) George Magklaras -- Steelcyber Scientific

#POFR - Penguin OS Forensic (or Flight) Recorder - 
#A program that collects stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System 
#and derivatives.
#Copyright (C) 2021 Georgios Magklaras

#Meteorologisk Institutt/The Norwegian Meteorological Institute, hereby disclaims all copyright interest in the program
#`POFR' (A program that collects stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System and derivatives ) written by Georgios Magklaras, 
#Arnstein Orten, February 1 2021, Assistant Director for IT infrastructure


#This program is free software; you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation; either version 2 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License along
#with this program; if not, write to the Free Software Foundation, Inc.,
#51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

use strict;

use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use POSIX;
use IO::Compress::Gzip;

#Sampling delay - increased for dev mode. Originally at 300000.
my $sdelay=300000;
my $netpid="$$";
my $startdelay=1000000;
my $sendprocpid;

#Sanity checks
#Is there a .netpid file?
if (-e ".netpid") {
	die "scannet.pl Error: Found a .netpid file. This means that it is eiher a scanproc.pl process running OR this is a stale file. In this latter case, please check first and if necessary remove the stale .netpid file and try again.\n";
} else {
	open(my $netfh, ">" ,".netpid") or die "scannet.pl Error: Could not open the .netpid file for writing due to: $!";
	print $netfh "$netpid";
	close $netfh;
}

#Wait until the client startup script forks/starts the sendproc.pl script
#and then read the pid to send it as part of the data. In contrast to the 
#scanproc.pl script, we only send the pid of the sendproc.pl script as part 
#of the data, because scanproc.pl and scannet.pl do not create endpoints.
usleep($startdelay);
if (-e ".sendpid") {
	open my $s, ".sendpid";
	{
		local $/;
		$sendprocpid=<$s>;
	}
	close $s;

	} else {

	unlink ".netpid";
	die "scannet.pl Error: Could not find a .sendpid file. Probably sendproc.pl could not create it OR you are executing the script outside the client startup scripts. In the latter case, please do not call scannet.pl directly but use the client startup scripts. \n";

}


while (1==1) {
	
	my $timeref;
	my ($secs, $microsecs)=gettimeofday();
	my $tz=strftime("%z", localtime());
	#Pad with zeros the microsecs field as
	#we are going to contruct a file name with that string 
	#that needs to be consistent in terms of length and number.
	my $pmicrosecs=sprintf( "%06d", $microsecs );

	#Get the IPv4 endpoints
	open(TCPFD, "<","/proc/net/tcp");
	my @tcpv4=<TCPFD>;
	close(TCPFD);
	open(UDPFD, "<","/proc/net/udp");
	my @udpv4=<UDPFD>;
	close(UDPFD);

	#Get the IPv6 endpoints
	open(TCPFD6, "<","/proc/net/tcp6");
        my @tcpv6=<TCPFD6>;
        close(TCPFD6);
        open(UDPFD6, "<","/proc/net/udp6");
        my @udpv6=<UDPFD6>;
        close(UDPFD6);
	
	#Here we construct the filename from the time stamp
	my $WRDNETZ= new IO::Compress::Gzip("/dev/shm/$secs$pmicrosecs#$tz.net.gz");
	#open WRDNET , ">", "/dev/shm/$secs$pmicrosecs-$tz.net";
	select $WRDNETZ;
	$WRDNETZ->print("@tcpv4###@tcpv6###@udpv4###@udpv6");
	close($WRDNETZ);
	
	usleep($sdelay);
} #end of infinite  while loop
