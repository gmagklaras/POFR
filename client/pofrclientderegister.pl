#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.36.0/x86_64-linux -I ../pofrperl/lib/5.36.0
#
use lib '../pofrperl/lib/site_perl/5.36.0';

#pofrclientderegister.pl: CLIENT side module that cleans a registered POFR client
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

use Data::Dumper;
use DBI;
use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use Digest::SHA qw(sha1 sha1_hex sha256_hex);
use Digest::MD5 qw(md5_hex);
use Getopt::Long;
use File::Path qw(make_path remove_tree);;


my $helpflag;
my $batchflag;

#Sanity checks
my @whoami=getpwuid($<);
die "pofrclientderegister.pl Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0);

sub dispusage {
        print "Usage:	pofrclientderegister.pl [--batch]  \n";
        print "Example 1: pofrclientderegister.pl \n";
	print "Example 2: pofrclientderegister.pl --batch (will not ask you to verify with a y/n) \n";
        exit;
}

GetOptions("batch" => \$batchflag, 
           "help" => \$helpflag );


if ($helpflag) {
        dispusage;
}


if (!defined($batchflag)) {
	print "pofrclientderegister.pl STATUS: WARNING: YOU ARE ABOUT TO REMOVE THIS CLIENT REGISTRATION STATE FILES. \n";
	print "pofrclientderegister.pl STATUS: Are you sure you wish to remove them from the system? (y/n)";
        my $ynanswer=<STDIN>;
	chomp $ynanswer;
	if ($ynanswer eq "n") { 
		die "pofrclientderegister.pl STATUS: Operator chose to abort. Exiting!...\n";
	} elsif ($ynanswer eq "y") {
		print "pofrclientderegister.pl STATUS: Operator chose to proceed with the process of removing the client registration files. \n";
		deregisterclient();
	} else {
		die "pofrclientderegister.pl Error: Invalid answer, please answer with y or n. Try again. \n";
	}
} else {
	print "pofrclientderegister.pl STATUS: --batch flag detected, proceeding with unregister the registration files from the client. \n";
	deregisterclient();
}

	
	 
#Subroutines here
sub getfsusername {
	#Obtains the filesystem username from the responsecid state file
	#to make the removal of clients easier.
	
	#Locate the responsecid.reg file
	my @responses = glob ("./response*.reg");

	#Take the first found file (it should be only one) and parse the contents
	open(REQ, "<","$responses[0]");
        my $creq=<REQ>;
        close(REQ);

	my @regdata=split "#",$creq;
	print "pofrclientderegister.pl STATUS: Inside the getusername subroutine function: Detected fs username $regdata[1] \n";

	return $regdata[1];

} #End of getfsusername subroutine

sub deregisterclient {
	my $fsuser=getfsusername();
	print "pofrclientderegister.pl STATUS: Detected fs username $fsuser \n";
	print "pofrclientderegister.pl STATUS: Inside the unregisterclient subroutine: Stopping all POFR client ACTIVE processes. \n";
	system "echo \$PWD; ./stopclient.pl";
	print "pofrclientderegister.pl STATUS: Removing all relevant files now \n";
	system "echo \$PWD; rm pofr_rsa pofr_rsa.pub .lcaf.dat response*";
	print "pofrclientderegister.pl STATUS: All done. This removed all POFR client registration files and stopped active processes. \n";
	print "pofrclientderegister.pl STATUS: Don't forget to run the pofrcleanreg.pl on the *POFR server* to fully complete the process of deregistering the client. \n";
	print "pofrclientderegister.pl STATUS: The exact command you need to type on the POFR server is: \n";
	print "pofrclientderegister.pl STATUS: ./pofrcleanreg.pl --usertoremove $fsuser \n";

} #End of deregisterclient subroutine

