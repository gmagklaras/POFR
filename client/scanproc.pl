#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.34.1/x86_64-linux -I ../pofrperl/lib/5.34.1
#
use lib '../pofrperl/lib/site_perl/5.34.1';

#scanproc.pl: This script parses the /proc filesystem for process and file event data 
#Started and stopped by the POFR CLIENT startclient.pl and stopclient.pl scripts.
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

my $sprocpid="$$";
#Sampling delay - Increased for development mode. Original value 300000.
my $sdelay=300000;
my $startdelay=1000000;
my $sendprocpid;
my $scannetpid;

#Some essential sanity checks 
#Is there a .scanpid file?
if (-e ".scanpid") {
#
        die "scanproc.pl Error: Found a .scanpid file. This means that it is eiher a scanproc.pl process running OR this is a stale file. In this latter case, please check first and if necessary remove the .stale .scanpid file and try again.\n";
	} else {

	open(my $scanfh, ">" ,".scanpid") or die "scanproc.pl Error: Could not open the .scanpid file for writing due to: $!";
	print $scanfh "$sprocpid";
	close $scanfh;

	}

#Before entering the loop report the last reboot time
my $c;
open my $P,"/proc/stat";
{
	local $/;
	$c= <$P>;
}
close $P;
my ($t)=($c =~ /btime\s(\d+)/);
open(my $fh, '>', '/dev/shm/lastreb.proc') or die "Could not write the lastreboot time info due to $!";
print $fh +localtime($t)."\n";
close $fh;

#Wait until the client startup script forks/starts the sendproc.pl and scannet.pl 
# scripts and then read their pids to send them.
usleep($startdelay);
if (-e ".sendpid") {
	open my $s, ".sendpid";
	{
		local $/;
		$sendprocpid=<$s>;
	}
	close $s;

	} else {
	#This is an aborted start, so clean the file and exit producing
	#an error message.
	unlink ".scanpid";
	die "scanproc.pl Error: Could not find a .sendpid file. Probably sendproc.pl could not create it OR you are executing the script outside the client startup scripts. In the latter case, please do not call scanproc.pl directly but use the client startup scripts. \n";

}


print "sendproc pid is: $sendprocpid \n";
$sprocpid="$sprocpid,$sendprocpid";

print "The combined pid string is $sprocpid \n";

while (1==1) {
	opendir(DIR, "/proc") || die "can't opendir /proc: $!";
	my @procs = grep { /^[1-9][0-9]*/  } readdir(DIR);
	closedir(DIR);

	my $timeref;

	#Debug
	#print "Processes are: @procs \n";

	#Get the timeref
	#open(TMR, "<","/proc/uptime");
	#my @timerefa=<TMR>;
	#close(TMR);
	my ($secs, $microsecs)=gettimeofday;
	my $tz=strftime("%z", localtime());

	#We need to pad the microsecs field with zeros
	#it is not always six digit long
	my $pmicrosecs=sprintf( "%06d", $microsecs );

	#my @timerefstr=split " ", $timerefa[0];

	#print "timerefstr is: @timerefstr \n";
	#$timeref=$timerefstr[0];
	#print "timeref is: $timeref\n";

	#$timeref=~ tr/'.'//d;

	#print "$timeref is now: $timeref \n";
	#Debug	
	#print "Pid is: $pspid. Time is: $timeref \n";


	my $WRDZ= new IO::Compress::Gzip("/dev/shm/$secs$pmicrosecs#$tz.proc.gz");

	#open WRD , ">", "/dev/shm/$secs$pmicrosecs-$tz.proc";
	foreach my $proc (@procs) {
	 	open(CMD, "<","/proc/$proc/cmdline");
	 	my $cmdline=<CMD>;
	 	close(CMD);
	 	if (!(defined $cmdline))  { $cmdline="--NOCMDARGENTRY--";}
		open(STA, "<","/proc/$proc/status");
	 	my @ppida=<STA>;
		#Depending on the version of the Linux kernel the structure
                #of /proc/pid/status differs. Earlier Linux kernels (2.6.x)
                #seem to contain the Ppid field on the fifth line [pos 4 starting from 0].
		#Newer kernels (3.10.x and 4.x and 5.x) seem to have it in the seventh line [pos 6 starting from zero]
	 	my @ppidstr=split ":", $ppida[6];
		my $ppid;
		if ( $ppidstr[0] eq 'PPid') {
			#We are dealing with a 3.10.x or 4.x kernel
			$ppid=$ppidstr[1]; 
		} else {
			#We are dealing with a 2.6.x older kernel
			my @oldppidstr=split ":", $ppida[4];
			$ppid=$oldppidstr[1];
		}

	 	my @namea=split ":", $ppida[0];
	 	my $name=$namea[1];
	 	#Remove white space from $ppid and $name
	 	$ppid=~ s/(^\s+|\s+$)//g;
	 	$name=~ s/(^\s+|\s+$)//g;
	 	my $uid;
	 	my @struid;
	 	my @euid;
	 	@struid=split ":", $ppida[6];
	 	#Depending on the version of the Linux kernel the structure
	 	#of /proc/pid/status differs. Earlier Linux kernels (2.6.x)
	 	#seem to contain the uid field in the seventh line [pos 6 starting from 0]. 
	 	#However, newer 4.x kernels have it in the ninth line [pos 8 starting from 0].
	 	#Thus, we check we are getting data from the right field here. 
	 	@euid=split "\t", $struid[1];
	 	if ( $euid[0] eq 'Uid') {
			#We are dealing with an older 2.6.x Linux kernel  
	 		$uid=$euid[1];
	 	} else { 
			#We are dealing with a 4.x/5.x Linux kernel and thus
			#we fish for the Uid field on the 9th line from the top. 
			@struid=split ":", $ppida[8];
			@euid=split "\t", $struid[1];
			$uid=$euid[1];
	 	 
	 	} #end of $euid[0]...

	 	#Remove any new line characters from uid
	 	chomp $uid;
	 	close(STA);
	 	opendir(FDD, "/proc/$proc/fd");
	 	my @fds = grep { /^[1-9][0-9]*/  } readdir(FDD);
	 	close(FDD);
	 	my @openfiles;
	 	foreach my $fd (@fds) {
			push(@openfiles,readlink"/proc/$proc/fd/$fd");
		} #end of foreach my $fd
    
    		if ($#openfiles=='-1') {
			select $WRDZ;
			$WRDZ->print("$sprocpid###$proc###$ppid###$uid###$name###$cmdline###LUARMv2NOOPENFILES \n"); } 
		else { 
			select $WRDZ;
			$WRDZ->print("$sprocpid###$proc###$ppid###$uid###$name###$cmdline###@openfiles \n"); 
    		}	

	 } #END OF foreach my $proc
	
	close($WRDZ);

	#Here we sample the network data now
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
	$WRDNETZ->print("$sprocpid###@tcpv4###@tcpv6###@udpv4###@udpv6");
	close($WRDNETZ);

	usleep($sdelay);
} #END OF while loop
