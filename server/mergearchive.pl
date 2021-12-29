#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.34.0/x86_64-linux -I ../pofrperl/lib/5.34.0
###
use lib '../pofrperl/lib/site_perl/5.34.0';

##mergearchive.pl -- This POFR engine script created the archive POFR tables, in order to reduce rendundancy of info. Called manually by the POFR server 
#administrator.

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
use warnings;
use DBI;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use IO::File;
use Getopt::Long;

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

my $helpflag;

sub dispusage {
        print "Usage:   mergearchive.pl USER_TO_MERGE \n";
        print "Example: mergearchive.pl 23b24050a74006f0f8d4f8b851bf454f \n";
        exit;
}

GetOptions("usertomerge=s" => \$usertoprocess,
           "help" => \$helpflag );


if ($helpflag) {
        dispusage;
}

if (! (defined($usertoprocess))) {
	print "mergearchive.pl Error: The user argument is not defined. I shall exit and do nothing! \n";
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
sub getdbauth {
        unless(open DBAUTH, "<./.adb.dat") {
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

sub producearchive {
	#Fetch the userid and dbname parameter names
	my $usertomerge=shift;
        my $ldb=shift;

	#Debug
	print "mergearchive.pl status: This is producearchive($usertomerge,$ldb) starting work...\n";
	 
	#Check to see if SELinux is in enforcing mode. Necessary for POFR production servers that have (and should have) SELinux on.
	my $selinuxmode=`getenforce`;
        chomp($selinuxmode);

	#Check to see if the /dev/shm/luarmserver/[userid]/temp exists
	if (-e "/dev/shm/luarmserver/$usertomerge/temp" && -d "/dev/shm/luarmserver/$usertomerge/temp") {
		print "mergearchive.pl status: Starting up, detected /dev/shm/luarmserver/$usertomerge/temp dir...\n";
		if ($selinuxmode eq "Enforcing") {
			print "mergearchive.pl status: Detected SELinux in Enforcing mode, good! Thus ensuring that the temp dir has the right target context and permissions...\n";
			system "chown -R mysql /dev/shm/luarmserver/$usertomerge/temp";
                        system "semanage fcontext -a -t mysqld_db_t /dev/shm/luarmserver/$usertomerge/temp";
                        system "restorecon -v /dev/shm/luarmserver/$usertomerge/temp";
		} else {
			 print "mergearchive.pl status: Detected SELinux not to be in Enforcing mode, OK, but it would be better to have it in Enforcing mode...\n";
		} #end of if ($selinuxmode eq "Enforcing") else
	} else {
		#Directory does not exist and we need to create it properly.
		#In contrast to mergetables that gets executed after a parse cycle, it is possible that a user will need to
		#merge archive tables WITHOUT having executed a parse cycle first. This might occur after a fresh server reboot and a call to mergearchives.pl. 
		#This can create a race hazard with a permission denied or directory cannot exist result. Thus creating the directory properly
		if (-e "/dev/shm/luarmserver" && -d "/dev/shm/luarmserver") {
			print "mergearchive.pl: Detected /dev/shm/luarmserver dir...Starting up! \n";} else {
			print "mergearchive.pl Status: Could not detect /dev/shm/luarmserver dir...Fresh boot? Creating it... \n";
			mkdir "/dev/shm/luarmserver";
		}
		
		if (!(-e "/dev/shm/luarmserver/$usertomerge" && "/dev/shm/luarmserver/$usertomerge")) {
			print "mergearchive.pl Status: Could not detect /dev/shm/luarmserver/$usertomerge dir...Creating it!";
			mkdir "/dev/shm/luarmserver/$usertomerge" or die "mergearchive.pl Error: Cannot create user $usertomerge directory under /dev/shm/luarmserver. Full memory or other I/O issue?: $! \n";
		}
		
		print "mergearchive.pl status: Starting up, not detected the /dev/shm/luarmserver/$usertomerge/temp dir.\n";
                print "mergearchive.pl status: First time we create archive tables for user $usertomerge, thus creating the temp dir...\n";
                mkdir "/dev/shm/luarmserver/$usertomerge/temp" or die "mergearchive.pl Error: Cannot create /dev/shm/luarmserver/$usertomerge/temp. Full disk or other I/O issue? : $! \n";
		system "chown -R mysql /dev/shm/luarmserver/$usertomerge/temp";
                system "chmod 755 /dev/shm/luarmserver/$usertomerge/temp";

		if ($selinuxmode eq "Enforcing") {
			print "mergearchive.pl status: Detected SELinux in Enforcing mode, good! Thus ensuring that the newly created temp dir has the right target context...\n";
                        system "semanage fcontext -a -t mysqld_db_t /dev/shm/luarmserver/$usertomerge/temp";
                        system "restorecon -v /dev/shm/luarmserver/$usertomerge/temp";
		} else {
			print "mergearchives.pl status: Detected SELinux not to be in Enforcing mode, OK, but it would be better to have it in Enforcing mode.Just created the temp dir and proceeding... \n";
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

	my @myparchtables=$hostservh->tables('', $ldb, 'archpsinfo%', 'TABLE');
	my @myfarchtables=$hostservh->tables('', $ldb, 'archfileinfo%', 'TABLE');
	my @mynarchtables=$hostservh->tables('', $ldb, 'archnetinfo%', 'TABLE');
	
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
	
	print "mergearchive.pl status: The producearchive sub is about to make the $pinf , $finf and $ninf period tables.\n";
	
	#DATA EXPORT TO FILE OPS
	foreach my $myptable (@myparchtables) {
		my $pdatafile="/dev/shm/luarmserver/$usertomerge/temp/periodpsdata$myptable".$pmergedstring.$usertomerge;
		#Export the data into CSV files residing in RAM;
		#obviously the order we SQL select the fields is important and needs to match that on of the table definition ( see @mergearchivesql)
		my $SQLh=$hostservh->prepare("SELECT psentity,shanorm,shafull,uid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec,dyear,dmonth,dday,dhour,dmin,dsec,dmsec INTO OUTFILE '$pdatafile' FIELDS TERMINATED BY '###' LINES TERMINATED BY '\n' from $myptable");
        	$SQLh->execute();
	}

	foreach my $myftable (@myfarchtables) {
		my $fdatafile="/dev/shm/luarmserver/$usertomerge/temp/periodfiledata$myftable".$pmergedstring.$usertomerge;
		#Export the data into CSV files residing in RAM;
		#obviously the order we SQL select the fields is important and needs to match that on of the table definition ( see @mergearchivesql)
		my $SQLh=$hostservh->prepare("SELECT fileaccessid,shasum,filename,uid,command,pid,ppid,tzone,cyear,cmonth,cday,cmin,chour,csec,cmsec,dyear,dmonth,dday,dhour,dsec,dmin,dmsec INTO OUTFILE '$fdatafile' CHARACTER SET utf8mb4 FIELDS TERMINATED BY '###' LINES TERMINATED BY '\n' from $myftable");
        	$SQLh->execute();
	}

	foreach my $myntable (@mynarchtables) {
		my $ndatafile="/dev/shm/luarmserver/$usertomerge/temp/periodnetdata$myntable".$pmergedstring.$usertomerge;
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

	for my $sqlst (@mergearchivesql) {
                $hostservh->do($sqlst);
        }

	#SQL INSERT from the in memory process data CSV file
	opendir(DIR, "/dev/shm/luarmserver/$usertoprocess/temp") || die "mergearchive.pl Error: producearchive sub: User $usertoprocess: During the in memory process file SQL insertion, it was impossible to opendir /dev/shm/luarmserver/$usertoprocess due to: $!";
	my @inmempfiles=sort grep { /^periodpsdata.{1,}/  } readdir(DIR);
	closedir(DIR);

	foreach my $inmemptoprocess (@inmempfiles) {
		open( my $pdata, "<", "/dev/shm/luarmserver/$usertoprocess/temp/$inmemptoprocess") or die "mergearchive.pl Error: Could not open process data CSV file dev/shm/luarmserver/$usertoprocess/temp/$inmemptoprocess due to: $!\n";
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
                                	print "mergearchives.pl Error: User $usertoprocess: Inside the IN MEM file data SQL insert for process data. No archive process record was altered. Record $line was not registered.\n";
                        	}
 			} #end of if if ( $shanormhits[0]=="1" || $shanormhits[0] >= "2" ) { else...
		} #end of while (my $line = <$pdata>)

	} #end of foreach $inmemptoprocess (@inmempfiles)

	#SQL INSERT from the in memory file data CSV file
	opendir(DIR, "/dev/shm/luarmserver/$usertoprocess/temp") || die "mergearchive.pl Error: producearchive sub: User $usertoprocess: During the in memory file data SQL insertion, it was impossible to opendir /dev/shm/luarmserver/$usertoprocess due to: $!";
	my @inmemffiles=sort grep { /^periodfiledata.{1,}/  } readdir(DIR);
	closedir(DIR);

	foreach my $inmemftoprocess (@inmemffiles) {
		open( my $fdata, '<', "/dev/shm/luarmserver/$usertoprocess/temp/$inmemftoprocess" ) or die "mergearchive.pl Error: Could not open file data CSV file dev/shm/luarmserver/$usertoprocess/temp/$inmemftoprocess due to: $!\n";
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
					print "mergearchives.pl Error: User $usertoprocess: Inside the IN MEM file data SQL insert for file data. No archive process record was altered. Record $line was not registered.\n";
				}
			}  #End of  if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) 
		} #End of  if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) {
	
	} # End of foreach my $inmemftoprocess (@inmemffiles)

	#SQL INSERT from the in memory net data CSV file
	opendir(DIR, "/dev/shm/luarmserver/$usertoprocess/temp") || die "mergearchive.pl Error: producearchive sub: User $usertoprocess: During the in memory net data SQL insertion, it was impossible to opendir /dev/shm/luarmserver/$usertoprocess due to: $!";
	my @inmemnfiles=sort grep { /^periodnetdata.{1,}/  } readdir(DIR);
	closedir(DIR);
	
	foreach my $inmemntoprocess (@inmemnfiles) {
		open( my $ndata, '<', "/dev/shm/luarmserver/$usertoprocess/temp/$inmemntoprocess" ) or die "mergearchive.pl Error: Could not open net data CSV file dev/shm/luarmserver/$usertoprocess/temp/$inmemntoprocess due to: $!\n";
		while (my $line = <$ndata>) {
			chomp $line;
			my @fields = split "###" , $line;
			$fields[14]=$hostservh->quote($fields[14]);
                	$fields[11]=$hostservh->quote($fields[11]);
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
					. "'$fields[27]','$fields[28]','$fields[29]')" );
				
				if (($rows==-1) || (!defined($rows))) {
					print "mergearchives.pl Error: User $usertoprocess: Inside the IN MEM net data SQL insert for file data. No archive process record was altered. Record $line was not registered.\n";
				}

			} #End of if ( $shasumhits[0]=="1" || $shasumhits[0] >= "2" ) {
		} #End of while (my $line = <$ndata>)
	} #End of foreach my $inmemntoprocess (@inmemnfiles)




	#At the end, delete the luarmserverdir files, release the database and remove the .archmerge flag file
	foreach my $pfiletodelete (@inmempfiles) {
		unlink "/dev/shm/luarmserver/$usertoprocess/temp/$pfiletodelete";
	}

	foreach my $ffiletodelete (@inmemffiles) {
		unlink "/dev/shm/luarmserver/$usertoprocess/temp/$ffiletodelete";
	}

	foreach my $nfiletodelete (@inmemnfiles) {
		unlink "/dev/shm/luarmserver/$usertoprocess/temp/$nfiletodelete";
	}

	print "mergearchive.pl:Cleaning up archive tables for user $usertoprocess ...\n";
	
	foreach my $myptabletodelete (@myparchtables) {
		my $SQLh=$hostservh->prepare("DROP TABLE $myptabletodelete");
		$SQLh->execute();
	}
	print "mergearchive.pl:cleaned up archived process tables: @myparchtables \n";

	foreach my $myftabletodelete (@myfarchtables) {
		my $SQLh=$hostservh->prepare("DROP TABLE $myftabletodelete");
		$SQLh->execute();
	}
	print "mergearchive.pl:cleaned up archived file tables: @myfarchtables \n";

	foreach my $myntabletodelete (@mynarchtables) {
		my $SQLh=$hostservh->prepare("DROP TABLE $myntabletodelete");
		$SQLh->execute();
	}
	print "mergearchive.pl:cleaned up archived network tables: @mynarchtables \n";

	$SQLh->finish();
	unlink "/home/$usertoprocess/.archmerge" or warn "mergearchive.pl Warning: Could not unlink the .archmerge file for user $usertoprocess due to: $!";

	print "mergearchive.pl: User $usertoprocess process archived tables are: $myparchtables[0] \n";
	print "pyear:$pyear, pmonth:$pmonth, pday:$pday, phour:$phour, pmin:$pmin, psec:$psec, pmsec:$pmsec \n";
        print "lyear:$lyear, lmonth:$lmonth, lday:$lday, lhour:$lhour, lmin:$lmin, lsec:$lsec, lmsec:$lmsec \n"
}	
