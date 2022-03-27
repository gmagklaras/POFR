#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.34.1/x86_64-linux -I ../pofrperl/lib/5.34.1 -I ../lib
##
use lib '../pofrperl/lib/site_perl/5.34.1';


#mergetables.pl : Called periodically by the POFR delta parser to reduce clutter and the number of actively parsed tables for better performance 

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

use POFR;
use strict;
use warnings;
use DBI;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use IO::File;
use Getopt::Long;


#Sanity checks
#
my @whoami=getpwuid($<);
die "mergetables.pl Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0);

if (!(-e "/usr/sbin/semanage")) {
	die "mergetables.pl error: semanage and restorecon utilities are missing from the system. Please consider installing them. I won't be able to crunch data securely and handle SELinux contexts without these tools.\n";
}
 
if (!(-e "/usr/sbin/getenforce")) {
	die "mergetables.pl Error: getenforce command is missing. Please consider install it. I won't be able to crunch data securely and handle SELinux contexts without these tools.\n";
}

#The archive interval value $archiveint is set to 48000 file records
#Do not adjust this if you do not know what you are doing, as it can 
#impact RDBMS performance.
#Steelcyber Scientific adjusts this on a customer/system tuning basis.
my $archiveint=130000;
#The $ptablenlimit is how many process tables we are allowed to have before we 
#produce archive tables. Too many open tables irregardless of the number of
#file records on relatively idle systems can hurt performance. Again leave the
#adjustment of this to Steelcyber Scientific engineers. 
my $ptablenlimit=191;

#Get the userid
my $usertoprocess=shift;

my $helpflag;

#Command line argument sanity checks
sub dispusage {
        print "Usage:   mergetables.pl USER_TO_MERGE \n";
        print "Example: mergetables.pl 23b24050a74006f0f8d4f8b851bf454f \n";
        exit;
}

GetOptions("usertomerge=s" => \$usertoprocess,
           "help" => \$helpflag );


if ($helpflag) {
        dispusage;
}

if (! (defined($usertoprocess))) {
        print "mergetables.pl Error: The user argument is not defined. I shall exit and do nothing! \n";
        dispusage();
}


#Sanity check - Does the user exist in the database?
#Get the list of database userids
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
	print "mergetables.pl STATUS: Detected user $usertoprocess in the database...\n";
} else {
	$SQLh->finish();
	die "mergetables.pl Error: main part: Could not detect user $usertoprocess in the database. Are you sure the lhltable is not out of sync? \n";
}

#Sanity check - Does the user's home directory exist?
if ((-e "/home/$usertoprocess") && -d ("/home/$usertoprocess")) {
	print "mergetables status: Found the filesystem directory for user $usertoprocess ... \n";
} else {
	$SQLh->finish();
	die "mergetables Error: main part: Could not find the filesystem directory for user $usertoprocess. Are you sure the filesystem directory is not out of sync with the lhltable contents? \n";
}
 
#Sanity check - Do we have a proper /dev/shm/luarmserver directory created for the user?
if (!(-e "/dev/shm/luarmserver/$usertoprocess" && "/dev/shm/luarmserver/$usertoprocess")) {
	mkdir "/dev/shm/luarmserver/$usertoprocess" or die "mergetables.pl Error: main part: Cannot create user $usertoprocess directory under /dev/shm/luarmserver. Full memory or other I/O issue?: $! \n";
}

#Sanity check - Does the user have POFR server threads and/or merge process flags?
my @threadflags = glob ("/home/$usertoprocess/.luarmthread*");
my $threadfsize=scalar @threadflags;
if ( ($threadfsize == 0) && !(-e "/home/$usertoprocess/.merge")) {
	print "mergetables.pl STATUS: main part: User $usertoprocess clear of active processing or merge threads, continuing...\n";
	open(my $mergeflagfh, ">" ,"/home/$usertoprocess/.merge") or die "mergetables.pl Error: Could not open the .merge file for writing for user $usertoprocess due to: $!";
} else {
	$SQLh->finish();
	die "mergetables.pl Error: main part: Cannot continue work on user $usertoprocess because I detected thread OR merge flags. Check it out please! \n";
}

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
		
#Sense whether we have more than $archiveint entries in the merged fileinfo table
$SQLh=$hostservh->prepare("SELECT count(*) from fileinfo" );
$SQLh->execute();
my @fileinfocounts=$SQLh->fetchrow_array();
		
#Sense how many tables we have in the database.
$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '$ldb' AND TABLE_NAME RLIKE 'psinfo' AND TABLE_NAME NOT RLIKE 'archpsinfo'");
$SQLh->execute();
my @numberofptables=$SQLh->fetchrow_array();
my $ptablesnumber=$numberofptables[0];
$SQLh->finish();

if ( ($fileinfocounts[0] >= $archiveint) || ( $ptablesnumber >= $ptablenlimit) ) {
	#Debug
	print "mergetables.pl STATUS: main part: User $usertoprocess: Found more than $archiveint hits on fileinfo: $fileinfocounts[0], OR more than $ptablenlimit ptable files: $ptablesnumber thus making archived merged tables \n";
	#Merge the existing tables before we archive them. 
	mergetables($usertoprocess,$ldb);
	usleep(10000000);
	#Now archive the tables.
	archivetables($usertoprocess,$ldb);
	unlink "/home/$usertoprocess/.merge" or warn "mergetables.pl Warning: main part: (archivetables) Could not unlink the .merge file for user $usertoprocess due to: $!";
} else {
	#Debug
	print "mergetables.pl STATUS: main part: User $usertoprocess: Less than $archiveint file hits: $fileinfocounts[0] OR less than $ptablenlimit ptable files: $ptablesnumber , thus continuing growing the merge tables.\n";
	mergetables($usertoprocess,$ldb);
	unlink "/home/$usertoprocess/.merge" or warn "mergetables.pl Warning: main part: (archivetables) Could not unlink the .merge file for user $usertoprocess due to: $!";
} 


#Subroutines here
#Subroutine mergetables
sub mergetables {
	#Fetch the userid and dbname parameter names
	my $usertomerge=shift;
	my $ldb=shift;

	#Check again to detect a race with the parseprocthreads
	my @racehazardflags = glob ("/home/$usertomerge/.luarmthread*");
        my $rhflagsize=scalar @racehazardflags;
	if ( ($rhflagsize != 0)) {
		unlink "/home/$usertomerge/.merge" or warn "mergetables.pl Warning: Could not unlink the .merge file for user $usertomerge due to: $!";		
		die "mergetables.pl Error: Inside mergetables subroutine: user $usertomerge: detected a race hazard with parseproc threads. Exiting! \n";
	}

	#Debug
	print "mergetables.pl status: Inside mergetables subroutine: This is mergetables($usertomerge,$ldb) starting work...\n";
	
	#Connect to the database of that user
	my @authinfo=getdbauth();
	my ($dbusername,$dbname,$dbpass,$hostname);

	foreach my $dbentry (@authinfo) {
        ($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
	}	

	my $datasource="DBI:MariaDB:$ldb:$hostname";
	my $hostservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	$hostservh->do('SET NAMES utf8mb4');
	
	print "mergetables.pl STATUS: User $usertomerge: Inside the mergetables subroutine and about to drop the psinfo, fileinfo and netinfo tables \n";
	#Before sensing the tables to merge, dropped any previously merged tables
	#This is essential, as it might create a race hazard if you do not do it before 
	#sensing the tables.
	my @dtsql= (
        	"DROP TABLE IF EXISTS psinfo;",
                "DROP TABLE IF EXISTS fileinfo;",
                "DROP TABLE IF EXISTS netinfo;",
        );

        for my $sqlst (@dtsql) {
        	$hostservh->do($sqlst);
        }

	print "mergetables.pl STATUS: User $usertomerge: Inside the mergetables subroutine and dropped tables, about to sleep for 2 secs. \n";
        #Wait for a couple of seconds. 
        usleep(2000000);

	#Get info on every ('%') TABLE entity in the "main" schema.  Catalog is blank
	#b/c DBD::SQLite and/or SQLite itself has no concept of catalogs.
	#using the DBI tables()
	my @pstables=$hostservh->tables('', $ldb, 'psinfo%', 'TABLE');
        my @filetables=$hostservh->tables('', $ldb, 'fileinfo%', 'TABLE');
        my @nettables=$hostservh->tables('', $ldb, 'netinfo%', 'TABLE');
        print "pstables is: @pstables \n, filetables is: @filetables \n, nettables is: @nettables \n ";
        
	#Now produce the union strings to go into the sql statements that makes the MERGE engine tables             
	my $psunionstr=join ( ',', @pstables);
        my $fileunionstr=join ( ',', @filetables);
        my $netunionstr=join ( ',', @nettables);

	#Debug
	print "psunionstr is: $psunionstr \n";
	print "fileunionstr is: $fileunionstr \n";
	
	#Now produce the new merged tables
	my @mergesql= (
                                "CREATE TABLE psinfo (
                                `psentity` bigint(20) NOT NULL AUTO_INCREMENT,
                                `shanorm` char(40) NOT NULL,
                                `shafull` char(40) NOT NULL,
                                `uid` mediumint NOT NULL,
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
                                ) ENGINE=MERGE UNION($psunionstr) AUTO_INCREMENT=19470 CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci INSERT_METHOD=NO;",

                                "CREATE TABLE fileinfo (
                                `fileaccessid` bigint NOT NULL AUTO_INCREMENT,
                                `shasum` char(40) NOT NULL,
                                `filename` varchar(4096) NOT NULL,
                                `uid` mediumint NOT NULL,
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
                                ) ENGINE=MERGE UNION($fileunionstr) AUTO_INCREMENT=246450 CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci INSERT_METHOD=NO;",

                                "CREATE TABLE netinfo (
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
                                ) ENGINE=MERGE UNION($netunionstr) CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci INSERT_METHOD=NO;"

                        );

	eval {
		
        	for my $sqlst (@mergesql) {
                	$hostservh->do($sqlst);
                }
			
	};

	if ($@) {
                die "mergetables Error: inside the mergetables subroutine for user $usertomerge: Could not recreate the psinfo,fileinfo and netinfo tables. Exiting!!! \n";
        }

	print "mergetables.pl STATUS: User $usertomerge: Inside the mergedtables subroutine and recreated the merged psinfo, fileinfo and netinfo tables. Bye! \n";
	#Debug
	#Eventually when all is done, release the RDBMS handler
	$hostservh->disconnect();
}

#Subroutine archivetables
sub archivetables {
	#Fetch the userid and dbname parameter names
	my $usertomerge=shift;
	my $ldb=shift;

	#Check again for race hazards with the parseproc.pl threads	
	my @racehazardflags = glob ("/home/$usertomerge/.luarmthread*");
        my $rhflagsize=scalar @racehazardflags;
        if ( ($rhflagsize != 0) ) {
                unlink "/home/$usertomerge/.merge" or warn "mergetables.pl Warning: Inside the archivetables subroutine: Could not unlink the .merge file for user $usertomerge due to: $!";
                die "mergetables.pl Error: user $usertomerge: Inside archivetables subroutine: detected a race hazard with parseproc threads. Exiting! \n";
        }

	#Debug
	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: This is archivetables($usertomerge,$ldb) starting work...\n";

	#Open a merge table file flag
	#open(my $mergeflagfh, ">" ,"/home/$usertomerge/.merge") or die "mergetables.pl Error:archivetables(): Could not open the .merge file for writing for user $usertomerge (/home/$usertomerge) due to: $!";
	 
	#Check to see if SELinux is in enforcing mode. Necessary for POFR production servers that have (and should have) SELinux on. 
        my $selinuxmode=`/usr/sbin/getenforce`;
        chomp($selinuxmode);
	
	#Check to see if the /dev/shm/luarmserver/[userid]/temp
	if (-e "/dev/shm/luarmserver/$usertomerge/temp" && -d "/dev/shm/luarmserver/$usertomerge/temp") {
                print "mergetables.pl STATUS: Inside the archivetables subroutine: Starting up, detected /dev/shm/luarmserver/$usertomerge/temp dir...\n";
                if ($selinuxmode eq "Enforcing") {
                        print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: Detected SELinux in Enforcing mode, good! Thus ensuring that the temp dir has the right target context...\n";
                        system "/usr/sbin/semanage fcontext -a -t mysqld_db_t /dev/shm/luarmserver/$usertomerge/temp";
                        system "/usr/sbin/restorecon -v /dev/shm/luarmserver/$usertomerge/temp";
                } else {
                        print "mergetables.pl STATUS: User $usertomerge: Inside archivetables function: Detected SELinux not to be in Enforcing mode, OK, but it would be better to have it in Enforcing mode...\n";
                } #end of if ($selinuxmode eq "Enforcing") else
	} else {
                print "mergetables.pl STATUS: User $usertomerge: Inside archivetables function: Starting up, not detected the /dev/shm/luarmserver/$usertomerge/temp dir.\n";
                print "mergetables.pl STATUS: User $usertomerge: Inside archivetables function: First time we create archive tables for user $usertomerge, thus creating the temp dir...\n";
                mkdir "/dev/shm/luarmserver/$usertomerge/temp" or die "mergetables.pl Error: Inside the archivetables subroutine: Cannot create /dev/shm/luarmserver/$usertomerge/temp. Full disk or other I/O issue? : $! \n";
		system "chown -R mysql /dev/shm/luarmserver/$usertomerge/temp";
		system "chmod 755 /dev/shm/luarmserver/$usertomerge/temp";

                if ($selinuxmode eq "Enforcing") {
                        print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: Detected SELinux in Enforcing mode, good! Thus ensuring that the newly created temp dir has the right target context...\n";
                        system "/usr/sbin/semanage fcontext -a -t mysqld_db_t /dev/shm/luarmserver/$usertomerge/temp";
                        system "/usr/sbin/restorecon -v /dev/shm/luarmserver/$usertomerge/temp";
                } else {
                        print "mergetables.pl STATUS: User $usertomerge: Inside archivetables function: Detected SELinux not to be in Enforcing mode, OK, but it would be better to have it in Enforcing mode.Just created the temp dir and proceeding... \n";
                } #end of if ($selinuxmode eq "Enforcing") else

	} #end of if (-e "/dev/shm/luarmserver/$usertomerge/temp" && -d "/dev/shm/luarmserver/$usertomerge/temp") else


	#Connect to the database
	my @authinfo=getdbauth();
        my ($dbusername,$dbname,$dbpass,$hostname);

        foreach my $dbentry (@authinfo) {
        ($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
        }

        my $datasource="DBI:MariaDB:$ldb:$hostname";
        my $hostservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	$hostservh->do('SET NAMES utf8mb4');

	my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec);
        my ($lyear,$lmonth,$lday,$lhour,$lmin,$lsec,$lmsec);

	#Get the first (pdata) and the last dates and times of the merged psinfodata
	$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from psinfo ORDER BY chour,cmin,csec,cmsec LIMIT 1" );
        $SQLh->execute();
        my @pdata=$SQLh->fetchrow_array();

	#Listifying the @pdata array
	($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@pdata[0..$#pdata];

	$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from psinfo ORDER BY chour DESC,cmin DESC,csec DESC LIMIT 1" );
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

	#Debug
	print "pyear:$pyear, pmonth:$pmonth, pday:$pday, phour:$phour, pmin:$pmin, psec:$psec, pmsec:$pmsec \n";
	print "lyear:$lyear, lmonth:$lmonth, lday:$lday, lhour:$lhour, lmin:$lmin, lsec:$lsec, lmsec:$lmsec \n";

	#The names of the archived merged tables are defined here.
	my $pmergedstring="$pyear$pmonth$pday$phour$pmin$psec"."to"."$lyear$lmonth$lday$lhour$lmin$lsec";
	my $pinf="archpsinfo".$pmergedstring;
	my $finf="archfileinfo".$pmergedstring;
	my $ninf="archnetinfo".$pmergedstring;

	#Debug
        print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: About to make the $pinf , $finf and $ninf archive tables.\n";

	#Now, we have to read all the already existing merged tables in memory, because we are going to drop them later,
	#to clean up the database.
	#Form a unique name for the files;
	my $pdatafile="/dev/shm/luarmserver/$usertomerge/temp/psdata".$pmergedstring.$usertomerge;
	my $fdatafile="/dev/shm/luarmserver/$usertomerge/temp/filedata".$pmergedstring.$usertomerge;
	my $netdatafile="/dev/shm/luarmserver/$usertomerge/temp/netdata".$pmergedstring.$usertomerge;
	
	#Export the data into CSV files residing in RAM;
	#obviously the order we SQL select the fields is important and needs to match that on of the table definition ( see @archivesql)
	$SQLh=$hostservh->prepare("SELECT psentity,shanorm,shafull,uid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec,dyear,dmonth,dday,dhour,dmin,dsec,dmsec INTO OUTFILE '$pdatafile' FIELDS TERMINATED BY '###' LINES TERMINATED BY '\n' from psinfo ORDER BY chour,cmin,csec,cmsec");
	$SQLh->execute();
	$SQLh=$hostservh->prepare("SELECT fileaccessid,shasum,filename,uid,command,pid,ppid,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec,dyear,dmonth,dday,dhour,dsec,dmin,dmsec INTO OUTFILE '$fdatafile' CHARACTER SET utf8mb4 FIELDS TERMINATED BY '###' LINES TERMINATED BY '\n' from fileinfo ORDER BY chour,cmin,csec,cmsec");
	$SQLh->execute();
	$SQLh=$hostservh->prepare("SELECT endpointinfo,cyear,cmonth,cday,chour,cmin,csec,cmsec,tzone,transport,sourceip,sourcefqdn,sourceport,destip,destfqdn,destport,ipversion,pid,uid,inode,dyear,dmonth,dday,dhour,dmin,dsec,dmsec,shasum,country,city INTO OUTFILE '$netdatafile' FIELDS TERMINATED BY '###' LINES TERMINATED BY '\n' from netinfo ORDER BY chour,cmin,csec,cmsec");
	$SQLh->execute();

	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: Exported the data into CSV files residing in RAM \n";

	#Now we have read the data in memory, it is time to start cleaning up the existing tables.
	#Starting from the merged tables
	my @dtsql= (
		"DROP TABLE IF EXISTS psinfo;",
	        "DROP TABLE IF EXISTS fileinfo;",
	        "DROP TABLE IF EXISTS netinfo;",
	);

	for my $sqlst (@dtsql) {
		$hostservh->do($sqlst);
	}
	
	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: Dropped the psinfo, fileinfo and netinfo tables \n";
	#Wait for a couple of seconds
	usleep(2000000);
	
	#And then the underlying numbered parseproc thread tables that we used to create the merged tables.
	my @pstables=$hostservh->tables('', $ldb, 'psinfo%', 'TABLE');
	my @filetables=$hostservh->tables('', $ldb, 'fileinfo%', 'TABLE');
	my @nettables=$hostservh->tables('', $ldb, 'netinfo%', 'TABLE');

	#Debug
	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: pstables is: @pstables \n, filetables is: @filetables \n, nettables is: @nettables \n ";

        foreach my $ptabletodrop (@pstables) {
        	$SQLh=$hostservh->prepare("DROP TABLE IF EXISTS $ptabletodrop");
                $SQLh->execute();
        }

        foreach my $ftabletodrop (@filetables) {
        	$SQLh=$hostservh->prepare("DROP TABLE IF EXISTS $ftabletodrop");
                $SQLh->execute();
        }

        foreach my $ntabletodrop (@nettables) {
        	$SQLh=$hostservh->prepare("DROP TABLE IF EXISTS $ntabletodrop");
                $SQLh->execute();
        }

	#Now we produce the archived tables.
	my @archivesql= (
                                "CREATE TABLE $pinf (
                                `psentity` bigint(20) NOT NULL AUTO_INCREMENT,
                                `shanorm` char(40) NOT NULL,
                                `shafull` char(40) NOT NULL,
                                `uid` mediumint NOT NULL,
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
                                `uid` mediumint NOT NULL,
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
        
	for my $sqlst (@archivesql) {
        	$hostservh->do($sqlst);
        }
    
	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: Created the table schema for archive tables. \n";
	#SQL INSERT in memory process data CSV file
	open( my $pdata, '<', $pdatafile) or die "mergetables.pl Error: Inside the archivetables subroutine: Could not open process data CSV file $pdatafile due to: $!\n";
	while (my $line = <$pdata>) {
		chomp $line;
		my @fields = split "###" , $line;
		#There might be special characters on the command line arguments, so quote them
		$fields[7]=$hostservh->quote($fields[7]);		
		#Here we need to find duplicate records before we insert 
		my $SQLph=$hostservh->prepare("SELECT COUNT(*) FROM $pinf WHERE shanorm='$fields[1]' ");
		$SQLph->execute();
		my @shanormhits=$SQLph->fetchrow_array();
		if ( $shanormhits[0]=="1" || $shanormhits[0] >= "2" ) {
			#Record exists do not insert. 
		} else {
			#Do insert the record 
			my $rows=$hostservh->do ("INSERT INTO $pinf (shanorm,shafull,uid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec)"
                                 	. "VALUES ('$fields[1]','$fields[2]','$fields[3]','$fields[4]','$fields[5]','$fields[6]',$fields[7],"
                               		. "'$fields[8]','$fields[9]','$fields[10]','$fields[11]','$fields[12]','$fields[13]','$fields[14]','$fields[15]')" );
			if (($rows==-1) || (!defined($rows))) {
                		print "mergetables.pl Error: Inside the archivetables subroutine: No archive process record was altered. Record $line was not registered.\n";
                	}	

		} #end of if if ( $shanormhits[0]=="1" || $shanormhits[0] >= "2" ) { else...

	} #end of while (my $line = <$pdata>)

	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: Made the $pinf table \n";

	#SQL INSERT in memory file data CSV file
	open( my $fdata, '<', $fdatafile) or die "mergetables.pl Error: Inside the archivetables subroutine: Could not open file data CSV file $pdatafile due to: $!\n";
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
                	my $rows=$hostservh->do ("INSERT INTO $finf (shasum,filename,uid,command,pid,ppid,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec)"
                                        . "VALUES ('$fields[1]',$fields[2],'$fields[3]','$fields[4]','$fields[5]','$fields[6]','$fields[7]',"
                                        . "'$fields[8]','$fields[9]','$fields[10]','$fields[11]','$fields[12]','$fields[13]','$fields[14]')" );
                	if (($rows==-1) || (!defined($rows))) {
                        	print "mergetables.pl Error: Inside the archivetables subroutine: No archive file record was altered. Record $line was not registered.\n";
                	}
		} #End of  if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) {

	} #end of while (my $line = <$fdata>)
	
	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: Made the $finf table \n";

	#SQL INSERT in memory network data CSV file
	open( my $ndata, '<', $netdatafile) or die "mergetables.pl Error: Inside the archivetables subroutine: Could not open net data CSV file $netdatafile due to: $!\n";
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
                        	print "mergetables.pl Error: Inside the archivetables subroutine: No archive net record was altered. Record $line was not registered.\n";
                	}	
		} #End of if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) {

        } #end of while (my $line = <$ndata>)

	print "mergetables.pl STATUS: Inside archivetables subroutine: User $usertomerge: Created the archivetables $pinf, $finf and $ninf. \n";

	#At that point, we need to recreate the psinfo,fileinfo,netinfo tables in their pristine non MERGE engine state
	my @recreatetables=(
		"CREATE TABLE `psinfo` (
  		`psentity` bigint(20) NOT NULL AUTO_INCREMENT,
  		`shanorm` char(40) NOT NULL,
  		`shafull` char(40) NOT NULL,
  		`uid` mediumint NOT NULL,
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
  		PRIMARY KEY (`psentity`)
		) ENGINE=MyISAM AUTO_INCREMENT=19470 CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",

		"CREATE TABLE `fileinfo` (
  		`fileaccessid` bigint NOT NULL AUTO_INCREMENT,
  		`shasum` char(40) NOT NULL,
  		`filename` varchar(4096) NOT NULL,
  		`uid` mediumint NOT NULL,
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
  		`dmin` tinyint(4) DEFAULT NULL,
  		`dmsec` mediumint(6) DEFAULT NULL,
  		PRIMARY KEY (`fileaccessid`)
		) ENGINE=MyISAM AUTO_INCREMENT=246450 CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",

		"CREATE TABLE `netinfo` (
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
		) ENGINE=MyISAM AUTO_INCREMENT=2075 CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"

	);

	eval {

		for my $rsqlst (@recreatetables) {
			$hostservh->do($rsqlst);		
		}

	};

	if ($@) {
		die "mergetables Error: inside the archivetables subroutine: User $usertomerge: Could not recreate the psinfo,fileinfo and netinfo tables. Exiting!!! \n";
	}
		
	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: REMADE the psinfo, fileinfo and netinfo tables in their pristine state. \n";

	#Remove the temporary SQL outfiles created to produce the archive tables.
	unlink $pdatafile or warn "mergetables.pl Warning: Inside the archivetables subroutine: Could not unlink the $pdatafile temporary process info file due to: $!";
	unlink $fdatafile or warn "mergetables.pl Warning: Inside the archivetables subroutine: Could not unlink the $fdatafile temporary file info file due to: $!";
	unlink $netdatafile or warn "mergetabples.pl Warning: Inside the archivetables subroutine: Could not unlink the $netdatafile temporary net info file due to: $!";

	#Further check for race hazard where we do not get the psinfo,fileinfo and netinfo tables
	if ( !((table_exists( $hostservh, "psinfo")) && (table_exists( $hostservh, "fileinfo")) && (table_exists( $hostservh, "netinfo"))) ) {
    		print "mergetables.pl status: Inside archivetables subroutine: User $usertomerge: FINAL CHECK: psinfo, fileinfo and netinfo tables present! \n";
	} else {
    		die "mergetables.pl Error: Inside archivetables subroutine: User $usertomerge: On FINAL CHECK: tables psinfo, fileinfo and netinfo not found! Exiting!! Please investigate detected race hazard! \n";
	}
	
	print "mergetables.pl STATUS: Inside the archivetables subroutine: User $usertomerge: I AM DONE, bye! \n";

	#Eventually when all is done, release the RDBMS handler
	$hostservh->disconnect();
	                        
}
