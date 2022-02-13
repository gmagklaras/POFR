#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.34.0/x86_64-linux -I ../pofrperl/lib/5.34.0
#
use lib '../pofrperl/lib/site_perl/5.34.0';

#pofrclientunregister.pl: CLIENT side module that cleans a registered POFR client
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
die "pofrclientunregister.pl Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0);

sub dispusage {
        print "Usage:	pofrclientunregister.pl [--batch]  \n";
        print "Example 1: pofrclientunregister.pl \n";
	print "Example 2: pofrclientunregister.pl --batch (will not ask you to verify with a y/n) \n";
        exit;
}

GetOptions("batch" => \$batchflag, 
           "help" => \$helpflag );


if ($helpflag) {
        dispusage;
}


if (!defined($batchflag)) {
	print "pofrclientunregister.pl STATUS: WARNING: YOU ARE ABOUT TO REMOVE THIS CLIENT REGISTRATION STATE FILES. \n";
	print "pofrclientunregister.pl STATUS: Are you sure you wish to remove them from the system? (y/n)";
        my $ynanswer=<STDIN>;
	chomp $ynanswer;
	if ($ynanswer eq "n") { 
		die "pofrclientunregister.pl STATUS: Operator chose to abort. Exiting!...\n";
	} elsif ($ynanswer eq "y") {
		print "pofrclientunregister.pl STATUS: Operator chose to proceed with the process of removing the client registration files. \n";
		unregisterclient();
	} else {
		die "pofrclientunregister.pl Error: Invalid answer, please answer with y or n. Try again. \n";
	}
} else {
	print "pofrclientunregister.pl STATUS: --batch flag detected, proceeding with unregister the registration files from the client. \n";
	unregisterclient();
}

	
	 
#Subroutines here
sub unregisterclient {
	print "pofrclientunregister.pl STATUS: Inside the unregisterclient subroutine: Stopping all POFR client ACTIVE processes. \n";
	system "echo \$PWD; ./stopclient.pl";
	print "pofrclientunregister.pl STATUS: Removing all relevant files now \n";
	system "echo \$PWD; rm .luarm* .lcaf.dat response*";
	print "pofrclientunregister.pl STATUS: All done. This removed all POFR client registration files and stopped active processes. \n";
	print "pofrclientunregister.pl STATUS: Don't forget to run the pofrcleanreg.pl on the *POFR server* to fully complete the process of unregistering the client. \n";

} #End of unregisterclient subroutine

sub getdbauth {
	#DBAUTH path hardwired only on the server side
	unless(open DBAUTH, "./.adb.dat") {
			die "lusreg Error:getdbauth: Could not open the .adb.dat file due to: $!";
		}

	my @localarray;	
	
	while (<DBAUTH>) {
		my $dbentry=$_;
		chomp($dbentry);
		push(@localarray, $dbentry);
	}

	return @localarray;	
	
} #end of getdbauth()


sub timestamp {
	#get the db authentication info
        my @authinfo=getdbauth();
        my ($username,$dbname,$dbpass,$hostname);

        foreach my $dbentry (@authinfo) {
                ($username,$dbname,$dbpass,$hostname)=split("," , $dbentry);
        }

        my $datasource="DBI:MariaDB:$dbname:$hostname";
        my $itpslservh=DBI->connect ($datasource, $username, $dbpass, {RaiseError => 1, PrintError => 1});

        my $SQLh=$itpslservh->prepare("select DATE_FORMAT(NOW(), '%Y-%m-%d-%k-%i-%s')");
        $SQLh->execute();

	my @timearray=$SQLh->fetchrow_array();
	my ($year,$month,$day,$hour,$min,$sec)=split("-",$timearray[0]);
	$SQLh->finish();
	return ($year,$month,$day,$hour,$min,$sec);
} #end of timestamp

