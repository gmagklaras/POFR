#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.36.0/x86_64-linux -I ../pofrperl/lib/5.36.0
#
use lib '../pofrperl/lib/site_perl/5.36.0';

#startclient.pl: A script to start the POFR client processes

#POFR - Penguin OS Forensic (or Flight) Recorder - 
#A program that collects stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System 
#and derivatives.
#Copyright (C) 2021,2022 Georgios Magklaras

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

use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use POSIX;

#my $startclientpid="$$";
my $sendprocpid;
my $scanprocpid;

#Sanity checks
#Are we root?
my @whoami=getpwuid($<);
die "startclient.pl Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0);

#Do we have the /bin/killall command installed? If yes, we need to.
if (!(-e "/bin/killall")) {
	die "starclient.pl error: You do not have the /bin/killall command installed. In the RedHat/CentOS/Fedora land of LINUX, this is part of the psmisc package (yum -y install psmisc OR dnf -y install psmisc). For the Debian/Ubuntu ecosystem, you might like to do a: apt install psmisc . Please fix before starting the client monitoring processes.\n";
}

#Sense the Linux Distro to check something
my %os=();

unless ( open(OS,"cat /etc/os-release|") ){
        print "ErrorOpenPipe OS_release";
        exit;
}

while (<OS>){
        my @os_param = split /=/, $_;
        $os{$os_param[0]}=$os_param[1];
}

print  $os{ID};
print  $os{VERSION_ID};

#Is there libnsl2 installed for Fedora?
if (!(-e "/usr/lib64/libnsl.so.1") && ($os{ID} eq "fedora")) {
	die "startclient.pl error: It seems that your Fedora is missing the libnsl library. I cannot send client data without it. Please install it with a dnf -y install libnsl. \n";
}

#Is there a sendproc.pl process running? If yes, let the one running
#to run. If not, start it up.
if (-e ".sendpid") {
	#Read the pid from the file 
	open my $sndp, ".sendpid";
	{
		local $/;
		$sendprocpid=<$sndp>;		        
	}
	close $sndp;
	#Is this pid really running?
	chomp (my $result=`ps auxwww | grep sendproc.pl | grep -v grep | grep $sendprocpid`);
	print "sendprocpid is: $sendprocpid \n";
	print "result is $result \n";
	
	if ( $result ) {
		print "startclient.pl Info: The sendproc.pl process is already running with pid $sendprocpid. \n";
	} else {
		#Here the sendproc.pl process had a stale .sendpid file and was not running
		unlink "./.sendpid" or die "startclient.pl Error: Could not remove the stale .sendpid file. Bye!";
		#Give sendproc.pl a clean start
		defined (my $pid=fork) or die "Startclient.pl Error: Cannot fork to launch the sendproc.pl client after a stale file removal: $! \n";
		unless ($pid) {
			exec "./sendproc.pl";
		}
	} #end of if ($result) else ...
} else {
	print "startclient.pl Info: Launching sendproc.pl module...\n";
	#No .sendpid file, clean sendproc.pl start
	defined (my $pid=fork) or die "Startclient.pl Error: Cannot fork to launcy the sendproc.pl client for a clean start: $! \n";
	unless ($pid) {
		exec "./sendproc.pl";
	}

} #end of if (-e ".sendpid") else...




#Are there a scanproc.pl process running? If yes, let 
#it run. If not, start it up.
#
if (-e ".scanpid") {
	print "scanproc.pl section \n";
	#read the pid from the file
	open my $scnp, ".scanpid";
	{
		local $/;
		$scanprocpid=<$scnp>;
	}
	close $scnp;
	#Is this pid really running?
	chomp (my $procres=`ps auxwww | grep scanproc.pl | grep -v grep | grep $scanprocpid`);

	if ( $procres ) {
		print "Startclient.pl Info: The scanproc client is already running with pid $scanprocpid. \n";
	} else {
		#Remove the stale .scanpid file as the scanproc.pl process is not running
		unlink "./.scanpid" or die "Startclient.pl Error: Cannot fork to launch the scanproc.pl client after a stale file removal: $! \n";
		#Give scanproc.pl a clean start
		defined (my $pid=fork) or die "Startclient.pl Error: Cannot fork to launch the scanproc.pl after a stale file removal: $! \n";
		unless ($pid) {
			exec "./scanproc.pl";
		}

	}#end of if ( $netres) else...
} else {
	print "startclient.pl Info: Launching scanproc.pl module...\n";
	#No .scanpid file, clean scanproc.pl start
	defined (my $pid=fork) or die "Startclient.pl Error: Cannot fork to launch the scanproc.pl for a clean start: $! \n";
        unless ($pid) {
                        exec "./scanproc.pl";
           } 
	
}#end of if (-e ".scanpid") ...


#Subroutine definitions
