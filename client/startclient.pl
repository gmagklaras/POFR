#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.32.1/x86_64-linux -I ../pofrperl/lib/5.32.1
#
use lib '../pofrperl/lib/site_perl/5.32.1';

#startclient.pl: A script to start the POFR client processes
#(C) George Maglaras - Steelcyber Scientific


use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use POSIX;

#my $startclientpid="$$";
my $sendprocpid;
my $scanprocpid;
my $snetpid;

#Sanity checks
#Are we root?
my @whoami=getpwuid($<);
die "startclient.pl Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0);

#Do we have the /bin/killall command installed? If yes, we need to.
if (!(-e "/bin/killall")) {
	die "starclient.pl error: You do not have the /bin/killall command installed. In the RedHat/CentOS/Fedora land of LINUX, this is part of the psmisc package (yum -y install psmisc OR dnf -y install psmisc). Please fix before starting the client monitoring processes.\n";
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




#Are there  scanproc.pl and scannet.pl processes running? If yes, let 
#them running together. If not, start them up together.
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

if (-e ".netpid") {
	print "scannet.pl section \n";
	#read the pid from the file
	open my $netp, ".netpid";
	{
		local $/;
		$snetpid=<$scnp>;
	}
	close $netp;

	#Is this pid really running?
	chomp (my $netres=`ps auxwww | grep scannet.pl | grep -v grep | grep $snetpid`);

	if ( $netres ) {
		print "Startclient.pl Info: The scannet.pl client is already running with pid $snetpid \n";
	} else {
		#Remove the stale .netpid file as the scannet.pl process is not running
		unlink "./.netpid" or die "Startclient.pl Error: Cannot remove the stale .netpid file: $! \n";
		#Fork a clean start
		defined (my $pid=fork) or die "Startclient.pl Error: Cannot fork to launch the scannet.pl after a stale file removal: $! \n";
		unless ($pid) {
			exec "./scannet.pl";
		}
	} #end of if ($netres) ...
} else {
	print "startclient.pl Info: Launching scannet.pl module...\n";
	defined (my $pid=fork) or die "Startclient.pl Error: Cannot fork to launch the scannet.pl for a clean start: $! \n";
	unless ($pid) {
		exec "./scannet.pl"; 
	}
}#end of if (-e ".netpid")...



#Subroutine definitions
