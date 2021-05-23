#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.32.1/x86_64-linux -I ../pofrperl/lib/5.32.1
#
use lib '../pofrperl/lib/site_perl/5.32.1';

#stopclient.pl: A script to stop the POFR client processes
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
#
chomp (my $result=`ps auxwww | grep sendproc.pl | grep -v grep`);
chomp (my $procres=`ps auxwww | grep scanproc.pl | grep -v grep`);
chomp (my $netres=`ps auxwww | grep scannet.pl | grep -v grep`);

if ($result || $procres || $netres) {
	system "killall -9 scanproc.pl scannet.pl; sleep 3; killall -9 sendproc.pl; rm .netpid; rm .scanpid; rm .sendpid";
} else {
	print "stopclient.pl Info: No active POFR client processes to stop. Exiting. \n";
}


		
