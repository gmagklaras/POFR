#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.38.2/x86_64-linux -I ../pofrperl/lib/5.38.2 -I ../lib
#
use lib '../pofrperl/lib/site_perl/5.38.2';

#scanproc.pl: This script parses the /proc filesystem for process and file event data 
#Started and stopped by the POFR CLIENT startclient.pl and stopclient.pl scripts.
#(C) George Magklaras -- Steelcyber Scientific

#POFR - Penguin OS Forensic (or Flight) Recorder - 
#A program that collects stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System 
#and derivatives.
#Copyright (C) 2021,2022,2023 Georgios Magklaras

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
use POFR;

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
	opendir(my $dir, "/proc") || die "can't opendir /proc: $!";
	my @procs = grep { -d "/proc/$_" && /^\d+$/ } readdir($dir);
	closedir($dir);

	my $timeref;

	my ($secs, $microsecs)=gettimeofday;
	my $tz=strftime("%z", localtime());

	#We need to pad the microsecs field with zeros
	#it is not always six digit long
	my $pmicrosecs=sprintf( "%06d", $microsecs );

	open(WRDZ, '>', "/dev/shm/$secs$pmicrosecs-$tz.proc") or die $!;
	
	foreach my $proc (@procs) {
	 	open(CMD, "<","/proc/$proc/cmdline");
	 	my $cmdline=<CMD>;
	 	close(CMD);
	 	if (!(defined $cmdline))  { $cmdline="--NOCMDARGENTRY--";}
		open my $fh, "<", "/proc/$proc/status";

		my %hash;

		while (my $line=<$fh>) {
    			chomp($line);
    			(my $field,my $value) = split /:/, $line;
    			$hash{$field} = $value;
		}
	
		close $fh;

		my $ppid=$hash{'PPid'};
		my $name=$hash{'Name'};
		#Remove white space from $ppid and $name
		$ppid=~ s/(^\s+|\s+$)//g;
		$name=~ s/(^\s+|\s+$)//g;

		#Remove the first white space charater from the hash string and then
		#split using white space as the separator
		my @struid=split(/\s+/, substr$hash{'Uid'},1);
		my @strgid=split(/\s+/, substr$hash{'Gid'},1);
		#the Uid: and Gid: fields of /proc/[pid]/status have currently the following form:
		#Uid, Gid: Real, effective, saved set, and file system UIDs (GIDs). 
		my $ruid=$struid[0];
		my $euid=$struid[1];
		my $rgid=$strgid[0];
		my $egid=$strgid[1];
	 	
		opendir(FDD, "/proc/$proc/fd");
	 	my @fds = grep { /^[1-9][0-9]*/  } readdir(FDD);
	 	close(FDD);
	 	my @openfiles;
	 	foreach my $fd (@fds) {
			#Sanitize the filename to ensure we do not have unwanted characters
			my $sfn=readlink"/proc/$proc/fd/$fd";
			$sfn=sanitize_filename($sfn);
			push(@openfiles,$sfn);

		} #end of foreach my $fd
    
		my $output;
                if (!@openfiles) {
                        $output = "$sprocpid###$proc###$ppid###$ruid###$euid###$rgid###$egid###$name###$cmdline###LUARMv2NOOPENFILES\n";
                } else {
                        $output = "$sprocpid###$proc###$ppid###$ruid###$euid###$rgid###$egid###$name###$cmdline###@openfiles\n";
                }
                print WRDZ $output;


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
	
	#Here we construct the network data filename from the time stamp
	open(WRDNETZ, '>', "/dev/shm/$secs$pmicrosecs-$tz.net") or die $!;
	$WRDNETZ->print("$sprocpid###@tcpv4###@tcpv6###@udpv4###@udpv6");
	close($WRDNETZ);

	usleep($sdelay);
} #END OF while loop
