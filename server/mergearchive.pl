#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.38.2/x86_64-linux -I ../pofrperl/lib/5.38.2 -I ../lib
###
use lib '../pofrperl/lib/site_perl/5.38.2';

##mergearchive.pl -- This POFR engine script created the archive POFR tables, in order to reduce rendundancy of info. Called manually by the POFR server 
#administrator.

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

use POFR;
use strict;
use warnings;
use DBI;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use IO::File;
use Getopt::Long;
use DateTime;
use DateTime::Format::Duration;


#Sanity checks
#
my @whoami=getpwuid($<);
die "mergearchive.pl Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0);

if (!(-e "/usr/sbin/semanage")) {
	die "mergearchive.pl error: semanage and restorecon utilities are missing from the system. Please consider installing them. I won't be able to crunch data securely and handle SELinux contexts without these tools.\n";
}

if (!(-e "/usr/sbin/getenforce")) {
	die "mergearchive.pl Error: getenforce command is missing. Please consider install it. I won't be able to crunch data securely and handle SELinux contexts without these tools.\n";
}

my $usertoprocess=shift;

#Do we want to specify date and time?
my $tspec;

#If we specify a date this is how we can specify it:
my ($fromday,$frommonth,$fromyear,$fromhour,$frommin,$fromsec,$today,$tomonth,$toyear,$tohour,$tomin,$tosec);

my $helpflag;

sub dispusage {
        print "Usage:   mergearchive.pl USER_TO_MERGE --tspec=y|n [--fromday=dd --frommonth=mm --fromyear=yyyy -fromhour=hh --frommin=mm --fromsec=ss --today=dd --tomonth=mm --toyear=yyyy --tohour=hh --tomin=mm --tosec=ss] \n";
        print "Example 1: mergearchive.pl 23b24050a74006f0f8d4f8b851bf454f --tspec=n \n";
	print "Example 2: mergearchive.pl 23b24050a74006f0f8d4f8b851bf454f --tspec=y --fromday=01 --frommonth=01 --fromyear=2022 --fromhour=00 --frommin=01 --fromsec=00 --today=02 --tomonth=02 --toyear=2022 --tohour=23 --tomin=45 --tosec=59 \n";
        exit;
}

GetOptions("usertomerge=s" => \$usertoprocess,
	   "tspec=s" => \$tspec,
	   "fromday=s" => \$fromday,
	   "frommonth=s" => \$frommonth, 
	   "fromyear=s" => \$fromyear,
	   "fromhour=s" => \$fromhour,
	   "frommin=s" => \$frommin,
	   "fromsec=s" => \$fromsec,
	   "today=s" => \$today,
           "tomonth=s" => \$tomonth,
           "toyear=s" => \$toyear,
           "tohour=s" => \$tohour,
           "tomin=s" => \$tomin,
           "tosec=s" => \$tosec,
           "help" => \$helpflag );


if ($helpflag) {
        dispusage;
}

#Command line argument sanity checks
if (! (defined($usertoprocess))) {
	print "mergearchive.pl Error: The user argument is not defined. I shall exit and do nothing! \n";
        dispusage();
}

if (! (defined($tspec))) {
	print "mergearchive.pl Error: The tspec argument is not defined. I shall exit and do nothing! \n";
	dispusage();
}

if (($tspec ne 'y') && ($tspec ne 'n')) {
	print "mergearchive.pl Error: The specified tspec argument is invalid. Please choose tspec=y OR tspec=n \n";
        dispusage();
}

if (($tspec eq 'y') && !( (defined($fromday)) && (defined($frommonth)) && (defined($fromyear)) && (defined($fromhour)) && (defined($frommin)) && (defined($fromsec)) 
	                  && (defined($today)) && (defined($tomonth)) && (defined($toyear)) && (defined($tohour)) && (defined($tomin)) && (defined($tosec)) )) {
	print "mergearchive.pl Error: You specified --tspec=y but it does not seem you specified all the necessary date and time arguments. Check again please. \n";
	dispusage();
}

if (($tspec eq 'n') && ( (defined($fromday)) || (defined($frommonth)) || (defined($fromyear)) || (defined($fromhour)) || (defined($frommin)) || (defined($fromsec))
                          || (defined($today)) || (defined($tomonth)) || (defined($toyear)) || (defined($tohour)) || (defined($tomin)) || (defined($tosec)) )) {
	print "mergearchive.pl Error: You specified --tspec=n but you also defined elements of date and time range. That does not make sense. Please try again. \n";
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
my $SQLh=$lhltservh->prepare("SELECT COUNT(*) FROM lhltable where ciduser='$usertoprocess'");
$SQLh->execute();
my @cidhits=$SQLh->fetchrow_array();
if ($cidhits[0] >= "1") {
        print "mergearchive.pl status: Detected user $usertoprocess in the database...\n";
} else {
        $SQLh->finish();
        die "mergearchive.pl Error: Could not detect user $usertoprocess in the database. Are you sure the lhltable is not out of sync? \n";
}

#Sanity check - Does the user's home directory exist?
if ((-e "/home/$usertoprocess") && -d ("/home/$usertoprocess")) {
        print "mergearchive.pl status: Found the filesystem directory for user $usertoprocess ... \n";
} else {
        $SQLh->finish();
        die "mergearchive.pl Error: Could not find the filesystem directory for user $usertoprocess. Are you sure the filesystem directory is not out of sync with the lhltable contents? \n";
}

#Sanity check - Does the user have POFR merge or archmerge process flags?
if (!( -e "/home/$usertoprocess/.archmerge") && !(-e "/home/$usertoprocess/.merge")) {
	print "mergearchive.pl status: User $usertoprocess clear of active merge or archive merge threads, continuing...\n";
	open(my $archmergeflagfh, ">" ,"/home/$usertoprocess/.archmerge") or die "mergearchives.pl Error: Could not open the .archmerge flag file for writing for user $usertoprocess due to: $!";
} else {
	$SQLh->finish();
	die "mergearchives.pl Error: Cannot continue work on user $usertoprocess because I detected merge OR archmerge flags. Please wait until current ops finish or check it out please! \n";
}

#Sanity check - If a specified date and time range was specified, is it within the range of the data we have in store?
if ( $tspec eq "y") {
	my $rangecheck=check_requested_data_time_range($usertoprocess,$fromday,$frommonth,$fromyear,$fromhour,$frommin,$fromsec,$today,$tomonth,$toyear,$tohour,$tomin,$tosec);
	if ($rangecheck eq "True") {
		print "mergearchive.pl STATUS: Requested date and time range seems to be available. Proceeding to retrieve the following data for user $usertoprocess: \n";
		print "mergearchive.pl STATUS: FROM Day:$fromday/Month:$frommonth/Year:$fromyear: $fromhour:$frommin:$fromsec \n";
		print "mergearchive.pl STATUS: TO   Day:$today/Month:$tomonth/Year:$toyear: $tohour:$tomin:$tosec \n";	
	} elsif ($rangecheck eq "False") {
	        print "mergearchive.pl Error: You are out of luck. Requested time range is not available. We do not have the requested data in store for user $usertoprocess: \n";
		print "mergearchive.pl Error: FROM Day:$fromday/Month:$frommonth/Year:$fromyear: $fromhour:$frommin:$fromsec \n";
		print "mergerachive.pl Error: TO   Day:$today/Month:$tomonth/Year:$toyear: $tohour:$tomin:$tosec \n";
		$SQLh->finish();
		unlink "/home/$usertoprocess/.archmerge";
		die "mergearchives.pl Error: I shall exit and do nothing! \n";
	} else {
		print "mergearchive.pl Error: The date and time query for user $usertoprocess is malformed. Query data: \n";      
                print "mergearchive.pl Error: FROM Day:$fromday/Month:$frommonth/Year:$fromyear: $fromhour:$frommin:$fromsec \n";
                print "mergerachive.pl Error: TO   Day:$today/Month:$tomonth/Year:$toyear: $tohour:$tomin:$tosec \n";
		$SQLh->finish();
		unlink "/home/$usertoprocess/.archmerge";
                die "mergearchives.pl Error: I shall exit and do nothing! \n";  
	}
} #End of if ( $tspec eq "y")
		

#Get the db name for that user
$SQLh=$lhltservh->prepare("SELECT cid FROM lhltable WHERE ciduser='$usertoprocess' ");
$SQLh->execute();
my @dbnamehits=$SQLh->fetchrow_array();
$SQLh->finish();
my $ldb=$dbnamehits[0];
$ldb =~ s/-//g;

#Connect to the user database now
my $userdb="DBI:MariaDB:$ldb:$hostname";
my $hostservh=DBI->connect ($userdb, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
$hostservh->do('SET NAMES utf8mb4');
#List the tables in an array
my @tablearray;
my @pstables;
my @filetables;
my @nettables;
my $string;

#Sense how many archive tables we have in the database.
$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '$ldb' AND TABLE_NAME RLIKE 'archpsinfo'");
$SQLh->execute();
my @numberofptables=$SQLh->fetchrow_array();
my $ptablesnumber=$numberofptables[0];
$SQLh->finish();

if ( $ptablesnumber >= 2 ) {
	producearchive($usertoprocess,$ldb);
} else {
	print "mergearchive.pl status: Found less than 2 archive tables, so no point doing the work, I will exit and do nothing. \n";
	unlink "/home/$usertoprocess/.archmerge" or warn "mergearchive.pl Warning: Could not unlink the .archmerge file for user $usertoprocess due to: $!";
}
	

#Subroutine definitions here
sub producearchive {
	#Fetch the userid and dbname parameter names
	my $usertomerge=shift;
        my $ldb=shift;

	#Debug
	print "mergearchive.pl STATUS: This is producearchive($usertomerge,$ldb) starting work...\n";
	 
	#Check to see if SELinux is in enforcing mode. Necessary for POFR production servers that have (and should have) SELinux on.
	my $selinuxmode=`getenforce`;
        chomp($selinuxmode);

	#Check to see if the /dev/shm/pofrserver/[userid]/temp exists
	if (-e "/dev/shm/pofrserver/$usertomerge/temp" && -d "/dev/shm/pofrserver/$usertomerge/temp") {
		print "mergearchive.pl STATUS: Inside the producearchive subroutine: Starting up, detected /dev/shm/pofrserver/$usertomerge/temp dir...\n";
		if ($selinuxmode eq "Enforcing") {
			print "mergearchive.pl status: Detected SELinux in Enforcing mode, good! Thus ensuring that the temp dir has the right target context and permissions...\n";
			system "chown -R mysql /dev/shm/pofrserver/$usertomerge/temp";
                        system "semanage fcontext -a -t mysqld_db_t /dev/shm/pofrserver/$usertomerge/temp";
                        system "restorecon -v /dev/shm/pofrserver/$usertomerge/temp";
		} else {
			 print "mergearchive.pl STATUS: Inside the producearchive subroutine: Detected SELinux not to be in Enforcing mode, OK, but it would be better to have it in Enforcing mode...\n";
		} #end of if ($selinuxmode eq "Enforcing") else
	} else {
		#Directory does not exist and we need to create it properly.
		#In contrast to mergetables that gets executed after a parse cycle, it is possible that a user will need to
		#merge archive tables WITHOUT having executed a parse cycle first. This might occur after a fresh server reboot and a call to mergearchives.pl. 
		#This can create a race hazard with a permission denied or directory cannot exist result. Thus creating the directory properly
		if (-e "/dev/shm/pofrserver" && -d "/dev/shm/pofrserver") {
			print "mergearchive.pl STATUS: Inside the producearchive subroutine: Detected /dev/shm/pofrserver dir...Starting up! \n";} else {
			print "mergearchive.pl STATUS: Inside the producearchive subroutine: Could not detect /dev/shm/pofrserver dir...Fresh boot? Creating it... \n";
			mkdir "/dev/shm/pofrserver";
		}
		
		if (!(-e "/dev/shm/pofrserver/$usertomerge" && "/dev/shm/pofrserver/$usertomerge")) {
			print "mergearchive.pl STATUS: Inside the producearchive subroutine: Could not detect /dev/shm/pofrserver/$usertomerge dir...Creating it!";
			mkdir "/dev/shm/pofrserver/$usertomerge" or die "mergearchive.pl Error: Inside the producearchive subroutine: Cannot create user $usertomerge directory under /dev/shm/pofrserver. Full memory or other I/O issue?: $! \n";
		}
		
		print "mergearchive.pl STATUS: Inside the producearchive subroutine: Starting up, not detected the /dev/shm/pofrserver/$usertomerge/temp dir.\n";
                print "mergearchive.pl STATUS: Inside the producearchive subroutine: First time we create archive tables for user $usertomerge, thus creating the temp dir...\n";
                mkdir "/dev/shm/pofrserver/$usertomerge/temp" or die "mergearchive.pl Error: Inside the producearchive subroutine: Cannot create /dev/shm/pofrserver/$usertomerge/temp. Full disk or other I/O issue? : $! \n";
		system "chown -R mysql /dev/shm/pofrserver/$usertomerge/temp";
                system "chmod 755 /dev/shm/pofrserver/$usertomerge/temp";

		if ($selinuxmode eq "Enforcing") {
			print "mergearchive.pl STATUS: Inside the producearchive subroutine: Detected SELinux in Enforcing mode, good! Thus ensuring that the newly created temp dir has the right target context...\n";
                        system "semanage fcontext -a -t mysqld_db_t /dev/shm/pofrserver/$usertomerge/temp";
                        system "restorecon -v /dev/shm/pofrserver/$usertomerge/temp";
		} else {
			print "mergearchives.pl STATUS: Inside the producearchive subroutine: Detected SELinux not to be in Enforcing mode, OK, but it would be better to have it in Enforcing mode.Just created the temp dir and proceeding... \n";
		} #end of if ($selinuxmode eq "Enforcing") else

	} #end of if (-e "/dev/shm/pofrserver/$usertomerge/temp" && -d "/dev/shm/pofrserver/$usertomerge/temp") else

	#Connect to the database
	my @authinfo=getdbauth();
        my ($dbusername,$dbname,$dbpass,$hostname);

        foreach my $dbentry (@authinfo) {
       		($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
        }

        my $datasource="DBI:MariaDB:$ldb:$hostname";
        my $hostservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
        $hostservh->do('SET NAMES utf8mb4');

	#The arrays that will hold the archive tables we are going to fuse/merge 
        my @myparchtables;
	my @myfarchtables;
	my @mynarchtables;

	#Did we specify a date and time range? If yes, include a subset of the tables as specified in the time range
	#If not, include everything that is stored for that user
	if ($tspec eq "y") {
		my ($procref,$fileref,$netref)=get_requested_data_from_time_range($usertomerge,$fromday,$frommonth,$fromyear,$fromhour,$frommin,$fromsec,$today,$tomonth,$toyear,$tohour,$tomin,$tosec);
		foreach my $mp (@$procref) {
			push (@myparchtables, $mp);
		}
		
		foreach my $mf (@$fileref) {
			push (@myfarchtables, $mf);
		}

		foreach my $mn (@$netref) {
			push (@mynarchtables, $mn);
		}

	} else {
		@myparchtables=$hostservh->tables('', $ldb, 'archpsinfo%', 'TABLE');
		@myfarchtables=$hostservh->tables('', $ldb, 'archfileinfo%', 'TABLE');
		@mynarchtables=$hostservh->tables('', $ldb, 'archnetinfo%', 'TABLE');
	}
	
	#Now we have to get the dates and times of the first and last piece of data
	#Select the first row of the first archpsinfo table
	my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec);
	my ($lyear,$lmonth,$lday,$lhour,$lmin,$lsec,$lmsec);

	my $SQLh;
	$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $myparchtables[0] LIMIT 1" );
	$SQLh->execute();
	my @pdata=$SQLh->fetchrow_array();

	#Listifying the @pdata array
	($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@pdata[0..$#pdata];
	
	#Then select the last record of the LAST archpsinfo table
	$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $myparchtables[-1] ORDER BY psentity DESC LIMIT 1" );
	$SQLh->execute();
        my @ldata=$SQLh->fetchrow_array();

	#Listifying the @ldata array
	($lyear,$lmonth,$lday,$lhour,$lmin,$lsec,$lmsec)=@ldata[0..$#ldata];
	
	#We need to padd certain vars with zeros so that they have two digit length
	#so that the output of SHOW TABLES is numerically sorted properly
	$pmonth = sprintf("%02d", $pmonth);
        $lmonth = sprintf("%02d", $lmonth);
        $pday = sprintf("%02d", $pday);
        $lday = sprintf("%02d", $lday);
        $phour = sprintf("%02d", $phour);
        $lhour = sprintf("%02d", $lhour);
        $pmin = sprintf("%02d", $pmin);
        $lmin = sprintf("%02d", $lmin);
        $psec = sprintf("%02d", $psec);
        $lsec = sprintf("%02d", $lsec);

	#The names of the produced merged archive tables are defined here.
	my $pmergedstring="$pyear$pmonth$pday$phour$pmin$psec"."to"."$lyear$lmonth$lday$lhour$lmin$lsec";
	my $pinf="periodprocess".$pmergedstring;
	my $finf="periodfile".$pmergedstring;
	my $ninf="periodnet".$pmergedstring;
	
	print "mergearchive.pl STATUS: Inside the producearchive subroutine: The producearchive sub is about to make the $pinf , $finf and $ninf period tables.\n";
	
	#DATA EXPORT TO FILE OPS
	foreach my $myptable (@myparchtables) {
		my $pdatafile="/dev/shm/pofrserver/$usertomerge/temp/periodpsdata$myptable".$pmergedstring.$usertomerge;
		#Export the data into CSV files residing in RAM;
		#obviously the order we SQL select the fields is important and needs to match that on of the table definition ( see @mergearchivesql)
		my $SQLh=$hostservh->prepare("SELECT psentity,shanorm,shafull,ruid,euid,rgid,egid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec,dyear,dmonth,dday,dhour,dmin,dsec,dmsec INTO OUTFILE '$pdatafile' FIELDS TERMINATED BY '###' LINES TERMINATED BY '\n' from $myptable");
        	$SQLh->execute();
	}

	foreach my $myftable (@myfarchtables) {
		my $fdatafile="/dev/shm/pofrserver/$usertomerge/temp/periodfiledata$myftable".$pmergedstring.$usertomerge;
		#Export the data into CSV files residing in RAM;
		#obviously the order we SQL select the fields is important and needs to match that on of the table definition ( see @mergearchivesql)
		my $SQLh=$hostservh->prepare("SELECT fileaccessid,shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec,dyear,dmonth,dday,dhour,dsec,dmin,dmsec INTO OUTFILE '$fdatafile' CHARACTER SET utf8mb4 FIELDS TERMINATED BY '###' LINES TERMINATED BY '\n' from $myftable");
        	$SQLh->execute();
	}

	foreach my $myntable (@mynarchtables) {
		my $ndatafile="/dev/shm/pofrserver/$usertomerge/temp/periodnetdata$myntable".$pmergedstring.$usertomerge;
		#Export the data into CSV files residing in RAM;
		#obviously the order we SQL select the fields is important and needs to match that on of the table definition ( see @mergearchivesql)
		my $SQLh=$hostservh->prepare("SELECT endpointinfo,cyear,cmonth,cday,chour,cmin,csec,cmsec,tzone,transport,sourceip,sourcefqdn,sourceport,destip,destfqdn,destport,ipversion,pid,uid,inode,dyear,dmonth,dday,dhour,dmin,dsec,dmsec,shasum,country,city INTO OUTFILE '$ndatafile' FIELDS TERMINATED BY '###' LINES TERMINATED BY '\n' from $myntable");
		$SQLh->execute();
	}

	#Now we produce the merged archive tables;
	my @mergearchivesql= (
                                "CREATE TABLE $pinf (
                                `psentity` bigint(20) NOT NULL AUTO_INCREMENT,
                                `shanorm` char(40) NOT NULL,
                                `shafull` char(40) NOT NULL,
				`ruid` mediumint NOT NULL,
                                `euid` mediumint NOT NULL,
                                `rgid` mediumint NOT NULL,
                                `egid` mediumint NOT NULL,
                                `pid` mediumint NOT NULL,
                                `ppid` mediumint NOT NULL,
                                `command` text NOT NULL,
                                `arguments` mediumtext,
                                `tzone` char(6) NOT NULL,
                                `cyear` smallint(6) NOT NULL,
                                `cmonth` tinyint(4) NOT NULL,
                                `cday` tinyint(4) NOT NULL,
                                `cmin` tinyint(4) NOT NULL,
                                `chour` tinyint(4) NOT NULL,
                                `csec` tinyint(4) NOT NULL,
                                `cmsec` mediumint(6) NOT NULL,
                                `dyear` smallint(6) DEFAULT NULL,
                                `dmonth` tinyint(4) DEFAULT NULL,
                                `dday` tinyint(4) DEFAULT NULL,
                                `dhour` tinyint(4) DEFAULT NULL,
                                `dmin` tinyint(4) DEFAULT NULL,
                                `dsec` tinyint(4) DEFAULT NULL,
                                `dmsec` mediumint(6) DEFAULT NULL,
                                PRIMARY KEY(`psentity`)
                                ) ENGINE=MyISAM CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",

                                "CREATE TABLE $finf (
                                `fileaccessid` bigint(20) NOT NULL AUTO_INCREMENT,
                                `shasum` char(40) NOT NULL,
                                `filename` varchar(4096) NOT NULL,
				`ruid` mediumint NOT NULL,
                                `euid` mediumint NOT NULL,
                                `rgid` mediumint NOT NULL,
                                `egid` mediumint NOT NULL,
                                `command` text NOT NULL,
                                `pid` mediumint NOT NULL,
                                `ppid` mediumint NOT NULL,
                                `tzone` char(6) NOT NULL,
                                `cyear` smallint(6) NOT NULL,
                                `cmonth` tinyint(4) NOT NULL,
                                `cday` tinyint(4) NOT NULL,
                                `cmin` tinyint(4) NOT NULL,
                                `chour` tinyint(4) NOT NULL,
                                `csec` tinyint(4) NOT NULL,
                                `cmsec` mediumint(6) NOT NULL,
                                `dyear` smallint(6) DEFAULT NULL,
                                `dmonth` tinyint(4) DEFAULT NULL,
                                `dday` tinyint(4) DEFAULT NULL,
                                `dhour` tinyint(4) DEFAULT NULL,
                                `dsec` tinyint(4) DEFAULT NULL,
                                `dmin` tinyint(4) DEFAULT NULL,
                                `dmsec` mediumint(6) DEFAULT NULL,
                                PRIMARY KEY (`fileaccessid`)
                                ) ENGINE=MyISAM CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",

                                "CREATE TABLE $ninf (
                                `endpointinfo` bigint(20) NOT NULL AUTO_INCREMENT,
                                `cyear` smallint(6) NOT NULL,
                                `cmonth` tinyint(4) NOT NULL,
                                `cday` tinyint(4) NOT NULL,
                                `chour` tinyint(4) NOT NULL,
                                `cmin` tinyint(4) NOT NULL,
                                `csec` tinyint(4) NOT NULL,
                                `cmsec` mediumint(6) NOT NULL,
                                `tzone` char(6) NOT NULL,
                                `transport` tinytext NOT NULL,
                                `sourceip` tinytext NOT NULL,
                                `sourcefqdn` tinytext,
                                `sourceport` smallint(6) unsigned NOT NULL,
                                `destip` tinytext NOT NULL,
                                `destfqdn` tinytext,
                                `destport` smallint(6) unsigned NOT NULL,
                                `ipversion` tinyint(4) NOT NULL,
                                `pid` mediumint NOT NULL,
                                `uid` mediumint NOT NULL,
                                `inode` int unsigned NOT NULL,
                                `dyear` smallint(6) DEFAULT NULL,
                                `dmonth` tinyint(4) DEFAULT NULL,
                                `dday` tinyint(4) DEFAULT NULL,
                                `dhour` tinyint(4) DEFAULT NULL,
                                `dmin` tinyint(4) DEFAULT NULL,
                                `dsec` tinyint(4) DEFAULT NULL,
                                `dmsec` mediumint(6) DEFAULT NULL,
                                `shasum` char(40) NOT NULL,
				`country` varchar(32) DEFAULT NULL,
  				`city` varchar(64) DEFAULT NULL,
                                PRIMARY KEY (`endpointinfo`)
                                ) ENGINE=MyISAM CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"

        );

	for my $sqlst (@mergearchivesql) {
                $hostservh->do($sqlst);
        }

	#SQL INSERT from the in memory process data CSV file
	opendir(DIR, "/dev/shm/pofrserver/$usertoprocess/temp") || die "mergearchive.pl Error: Inside the producearchive subroutine: User $usertoprocess: During the in memory process file SQL insertion, it was impossible to opendir /dev/shm/pofrserver/$usertoprocess due to: $!";
	my @inmempfiles=sort grep { /^periodpsdata.{1,}/  } readdir(DIR);
	closedir(DIR);

	foreach my $inmemptoprocess (@inmempfiles) {
		open( my $pdata, "<", "/dev/shm/pofrserver/$usertoprocess/temp/$inmemptoprocess") or die "mergearchive.pl Error: Inside the producearchive subroutine: Could not open process data CSV file dev/shm/pofrserver/$usertoprocess/temp/$inmemptoprocess due to: $!\n";
		while (my $line = <$pdata>) {
			chomp $line;
               		my @fields = split "###" , $line;
			#There might be special characters on the command line arguments, so quote them
			$fields[10]=$hostservh->quote($fields[10]);
			#Here we need to find duplicate records before we insert
			my $SQLph=$hostservh->prepare("SELECT COUNT(*) FROM $pinf WHERE shanorm='$fields[1]' ");
			$SQLph->execute();
			my @shanormhits=$SQLph->fetchrow_array();
			if ( $shanormhits[0]=="1" || $shanormhits[0] >= "2" ) {
				#Record exists do not insert. 
			} else {
				#Do insert the record 
				my $rows=$hostservh->do ("INSERT INTO $pinf (shanorm,shafull,ruid,euid,rgid,egid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec)"
					. "VALUES ('$fields[1]','$fields[2]','$fields[3]','$fields[4]','$fields[5]','$fields[6]','$fields[7]',"
					. "'$fields[8]','$fields[9]',$fields[10],'$fields[11]','$fields[12]','$fields[13]','$fields[14]','$fields[15]','$fields[16]','$fields[17]','$fields[18]')" );
				if (($rows==-1) || (!defined($rows))) {
                                	print "mergearchives.pl Error: Inside the producearchive subroutine: User $usertoprocess: Inside the IN MEM file data SQL insert for process data. No archive process record was altered. Record $line was not registered.\n";
                        	}
 			} #end of if if ( $shanormhits[0]=="1" || $shanormhits[0] >= "2" ) { else...
		} #end of while (my $line = <$pdata>)

	} #end of foreach $inmemptoprocess (@inmempfiles)

	#SQL INSERT from the in memory file data CSV file
	opendir(DIR, "/dev/shm/pofrserver/$usertoprocess/temp") || die "mergearchive.pl Error: Inside the producearchive subroutine: User $usertoprocess: During the in memory file data SQL insertion, it was impossible to opendir /dev/shm/pofrserver/$usertoprocess due to: $!";
	my @inmemffiles=sort grep { /^periodfiledata.{1,}/  } readdir(DIR);
	closedir(DIR);

	foreach my $inmemftoprocess (@inmemffiles) {
		open( my $fdata, '<', "/dev/shm/pofrserver/$usertoprocess/temp/$inmemftoprocess" ) or die "mergearchive.pl Error: Inside the producearchive subroutine: Could not open file data CSV file dev/shm/pofrserver/$usertoprocess/temp/$inmemftoprocess due to: $!\n";
		while (my $line = <$fdata>) {
			chomp $line;
        		my @fields = split "###" , $line;
			#There might be special characters on the filename, so quote it
			$fields[2]=$hostservh->quote($fields[2]);
			my $SQLfh=$hostservh->prepare("SELECT COUNT(*) FROM $finf WHERE shasum='$fields[1]' ");
			$SQLfh->execute();
			my @shasumhits=$SQLfh->fetchrow_array();
			if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) {
				 #Record exists do not insert.
			} else {
				#Do insert the record
				my $rows=$hostservh->do ("INSERT INTO $finf (shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec)"
					. "VALUES ('$fields[1]',$fields[2],'$fields[3]','$fields[4]','$fields[5]','$fields[6]','$fields[7]',"
					. "'$fields[8]','$fields[9]','$fields[10]','$fields[11]','$fields[12]','$fields[13]','$fields[14]','$fields[15]','$fields[16]','$fields[17]')" );
				if (($rows==-1) || (!defined($rows))) {
					print "mergearchives.pl Error: Inside the producearchive subroutine: User $usertoprocess: Inside the IN MEM file data SQL insert for file data. No archive process record was altered. Record $line was not registered.\n";
				}
			}  #End of  if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) 
		} #End of  if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) {
	
	} # End of foreach my $inmemftoprocess (@inmemffiles)

	#SQL INSERT from the in memory net data CSV file
	opendir(DIR, "/dev/shm/pofrserver/$usertoprocess/temp") || die "mergearchive.pl Error: Inside the producearchive subroutine: User $usertoprocess: During the in memory net data SQL insertion, it was impossible to opendir /dev/shm/pofrserver/$usertoprocess due to: $!";
	my @inmemnfiles=sort grep { /^periodnetdata.{1,}/  } readdir(DIR);
	closedir(DIR);
	
	foreach my $inmemntoprocess (@inmemnfiles) {
		open( my $ndata, '<', "/dev/shm/pofrserver/$usertoprocess/temp/$inmemntoprocess" ) or die "mergearchive.pl Error: Inside the producearchive subroutine: Could not open net data CSV file dev/shm/pofrserver/$usertoprocess/temp/$inmemntoprocess due to: $!\n";
		while (my $line = <$ndata>) {
			chomp $line;
			my @fields = split "###" , $line;
			$fields[14]=$hostservh->quote($fields[14]);
                	$fields[11]=$hostservh->quote($fields[11]);
			#Quote also the country and city fields
			$fields[28]=$hostservh->quote($fields[28]);
			$fields[29]=$hostservh->quote($fields[29]);
			my $SQLnh=$hostservh->prepare("SELECT COUNT(*) FROM $ninf WHERE shasum='$fields[27]' ");
			$SQLnh->execute();
                	my @shasumhits=$SQLnh->fetchrow_array();
			if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) {
				#Record exists do not insert.
			} else {
				#Do insert the record.
				my $rows=$hostservh->do ("INSERT INTO $ninf (cyear,cmonth,cday,chour,cmin,csec,cmsec,tzone,transport,sourceip,sourcefqdn,sourceport,destip,destfqdn,destport,ipversion,pid,uid,inode,shasum,country,city)"
					. "VALUES ('$fields[1]','$fields[2]','$fields[3]','$fields[4]','$fields[5]','$fields[6]','$fields[7]',"
					. "'$fields[8]','$fields[9]','$fields[10]',$fields[11],'$fields[12]','$fields[13]',$fields[14],"
					. "'$fields[15]','$fields[16]','$fields[17]','$fields[18]','$fields[19]',"
					. "'$fields[27]',$fields[28],$fields[29])" );
				
				if (($rows==-1) || (!defined($rows))) {
					print "mergearchives.pl Error: Inside the producearchive subroutine: User $usertoprocess: Inside the IN MEM net data SQL insert for file data. No archive process record was altered. Record $line was not registered.\n";
				}

			} #End of if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) {
		} #End of while (my $line = <$ndata>)
	} #End of foreach my $inmemntoprocess (@inmemnfiles)




	#At the end, delete the pofrserverdir files, release the database and remove the .archmerge flag file
	foreach my $pfiletodelete (@inmempfiles) {
		unlink "/dev/shm/pofrserver/$usertoprocess/temp/$pfiletodelete";
	}

	foreach my $ffiletodelete (@inmemffiles) {
		unlink "/dev/shm/pofrserver/$usertoprocess/temp/$ffiletodelete";
	}

	foreach my $nfiletodelete (@inmemnfiles) {
		unlink "/dev/shm/pofrserver/$usertoprocess/temp/$nfiletodelete";
	}

	#print "mergearchive.pl STATUS: Inside the producearchive subroutine: Cleaning up archive tables for user $usertoprocess ...\n";
	
	#foreach my $myptabletodelete (@myparchtables) {
	#	my $SQLh=$hostservh->prepare("DROP TABLE $myptabletodelete");
        #		$SQLh->execute();
	#}
	#print "mergearchive.pl STATUS:Inside the producearchive subroutine: Cleaned up archived process tables: @myparchtables \n";

	#foreach my $myftabletodelete (@myfarchtables) {
	#	my $SQLh=$hostservh->prepare("DROP TABLE $myftabletodelete");
	#	$SQLh->execute();
	#}
	#print "mergearchive.pl STATUS: Inside the producearchive subroutine: cleaned up archived file tables: @myfarchtables \n";

	#foreach my $myntabletodelete (@mynarchtables) {
	#	my $SQLh=$hostservh->prepare("DROP TABLE $myntabletodelete");
	#	$SQLh->execute();
	#}
	#print "mergearchive.pl STATUS: Inside the producearchive subroutine: Cleaned up archived network tables: @mynarchtables \n";

	$SQLh->finish();
	unlink "/home/$usertoprocess/.archmerge" or warn "mergearchive.pl Warning: Inside the producearchive subroutine: Could not unlink the .archmerge file for user $usertoprocess due to: $!";

	print "mergearchive.pl STATUS: Inside the producearchive subroutine: User $usertoprocess process archived tables are: $myparchtables[0] \n";
	print "pyear:$pyear, pmonth:$pmonth, pday:$pday, phour:$phour, pmin:$pmin, psec:$psec, pmsec:$pmsec \n";
        print "lyear:$lyear, lmonth:$lmonth, lday:$lday, lhour:$lhour, lmin:$lmin, lsec:$lsec, lmsec:$lmsec \n"
}	
