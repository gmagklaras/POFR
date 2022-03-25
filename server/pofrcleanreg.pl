#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.34.1/x86_64-linux -I ../pofrperl/lib/5.34.1 -I ../lib
#
use lib '../pofrperl/lib/site_perl/5.34.1';

#pofrcleanreg.pl: SERVER side module that removes a registered POFR client
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

use POFR;
use Data::Dumper;
use DBI;
use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use Digest::SHA qw(sha1 sha1_hex sha256_hex);
use Digest::MD5 qw(md5_hex);
use Getopt::Long;
use File::Path qw(make_path remove_tree);;

my $reghome="/home/pofrsreg";
my $userhome="/home";

my $usertoremove;
my $helpflag;
my $batchflag;

#Sanity checks
my @whoami=getpwuid($<);
die "pofrcleanreg.pl Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0);

#Sanity checks
opendir(DIR, $reghome) || die "pofrcleanreg.pl Error:can't open client registration directory: $!";
my @requests = grep { /^.*luarm$/ } readdir(DIR);
closedir(DIR);

sub dispusage {
        print "Usage:   pofrcleanreg.pl --usertoremove USER_TO_REMOVE [--batch]  \n";
        print "Example 1: pofrcleanreg.pl --usertoremove 23b24050a74006f0f8d4f8b851bf454f \n";
	print "Example 2: pofrcleanreg.pl --usertoremove 23b24050a74006f0f8d4f8b851bf454f --batch (will not ask you to verify with a y/n) \n";
        exit;
}

GetOptions("usertoremove=s" => \$usertoremove,
	   "batch" => \$batchflag, 
           "help" => \$helpflag );


if ($helpflag) {
        dispusage;
}

if (! (defined($usertoremove))) {
	print "pofrcleanreg.pl Error: The user argument is not defined. I shall exit and do nothing! \n";
        dispusage();
}

#Sanity check - Does the user exist in the database?
##Get the list of database userids
my @authinfo=getdbauth();
my ($dbusername,$dbname,$dbpass,$hostname);

foreach my $dbentry (@authinfo) {
        ($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
}

my $datasource="DBI:MariaDB:$dbname:$hostname";
my $lhltservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
my $SQLh=$lhltservh->prepare("SELECT COUNT(*) FROM lhlt.lhltable where ciduser='$usertoremove'");
$SQLh->execute();
my @cidhits=$SQLh->fetchrow_array();

if ($cidhits[0] == "0") {
	$SQLh->finish();
        die "pofrcleanreg.pl Error: I could not find $usertoremove in the database. I cannot remove that user. Please check and try again. \n";
} else {
	if (!defined($batchflag)) {
		print "pofrcleanreg.pl STATUS: Detected user to remove $usertoremove in the database. WARNING: YOU ARE ABOUT TO REMOVE THAT CLIENT FROM THE POFR DATABASE. \n";
		print "pofrcleanreg.pl STATUS: ALL DATA will be lost! Are you sure you wish to remove use $usertoremove from the system? (y/n)";
	        my $ynanswer=<STDIN>;
		chomp $ynanswer;
		if ($ynanswer eq "n") { 
			die "pofrcleanreg.pl STATUS: Operator chose to abort the removal of user $usertoremove. Exiting!...\n";
		} elsif ($ynanswer eq "y") {
			print "pofrcleanreg.pl STATUS: Operator chose to proceed with the removal of user $usertoremove. \n";
		} else {
			die "pofrcleanreg.pl Error: Invalid answer, please answer with y or n. Try again. \n";
		}
	}	
	print "pofrcleanreg.pl STATUS: Detected user to remove $usertoremove in the database. Proceeding with the removal. \n";
	#Get the db name for that user
	$SQLh=$lhltservh->prepare("SELECT cid FROM lhltable WHERE ciduser='$usertoremove' ");
	$SQLh->execute();
	my @dbnamehits=$SQLh->fetchrow_array();
	my $rdb=$dbnamehits[0];
	#Remove the entry from lhltable
	$SQLh=$lhltservh->prepare("DELETE FROM lhltable WHERE ciduser='$usertoremove' ");
	$SQLh->execute();
	print "pofrcleanreg.pl STATUS: Removed entry for user $usertoremove from the lhlt.lhltable. \n";
	#Now remove the database for that user
	$SQLh=$lhltservh->prepare("DROP DATABASE '$rdb' ");
	print "pofrcleanreg.pl STATUS: Removed database $rdb for user $usertoremove . \n";
	$SQLh->finish();

	#Sanity check - Does the user's home directory exist?
	if ((-e "/home/$usertoremove") && -d ("/home/$usertoremove")) {
        	print "pofrcleanreg.pl STATUS: Found the filesystem directory for user to remove $usertoremove ... \n";
		remove_tree("/home/$usertoremove", { verbose => 1, safe => 1},)  || die "pofrcleanreg.pl Error: Cannot remove user's $usertoremove filesystem directory due to: $!";
	        print "pofrcleanreg.pl STATUS: Filesystem directory for user $usertoremove removed. All good. Bye, bye! \n";	
		
	} else {
        	die "pofrcleanreg.pl Error: Could not find the filesystem directory for user to remove $usertoremove. Probably you have already removed it or things got out sync. Exiting... \n";
	}

}

