#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.36.0/x86_64-linux -I ../pofrperl/lib/5.36.0 -I ../lib
#
use lib '../pofrperl/lib/site_perl/5.36.0';

#pofrsreg.pl : SERVER side module that handles the POFR client registration requests
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

use POFR;
use Data::Dumper;
use DBI;
use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use Digest::SHA qw(sha1 sha1_hex sha256_hex);
use Digest::MD5 qw(md5_hex);

my $sdelay=400000;
my $reghome="/home/pofrsreg";
my $userhome="/home";

#Sanity checks
opendir(DIR, $reghome) || die "pofrsreg.pl Error:can't open client registration directory: $!";
my @requests = grep { /^.*luarm$/ } readdir(DIR);
closedir(DIR);

#Does the system have an scponly shell?
if (!(-e "/bin/scponly")) {
        die "pofrsreg.pl Error: An scponly shell seems to be missing from the system. Please consider installing it. I won't be able to make the account for the client system without it.\n";
}


foreach my $req (@requests) {
         open(REQ, "<","$reghome/$req");
         my $creq=<REQ>;
         close(REQ);
         my @reqdata=split "#",$creq;
	 my $clienthostname=shift @reqdata;
	 my $clientipaddress=shift @reqdata;
         my $uuid=shift @reqdata;
         my $cid=shift @reqdata;
         my $rsapk=shift @reqdata;

         #Some code that needs to check whether there is already a request processed
         #from the server RDBMS table needs to go here, in case we need to abort
         #the client registration (if it already exists).
         my @authinfo=getdbauth();
         my ($dbusername,$dbname,$dbpass,$hostname);

         foreach my $dbentry (@authinfo) {
                ($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
	 print "pofrsreg.pl STATUS: dbusername is: $dbusername, dbname is: $dbname on hostname: $hostname \n";
	 
         }
         
         my $datasource="DBI:MariaDB:$dbname:$hostname";
		 my $lhltservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
		 my $SQLh=$lhltservh->prepare("SELECT COUNT(*) FROM lhltable WHERE uuid='$uuid' ");
		 $SQLh->execute();
		 my @cidhits=$SQLh->fetchrow_array();
		 
		 #Does the record exist?
		 if ($cidhits[0]=="1") {
			#Record exists.
			#Make a response file with an error code to send to the client
			open(RESP, ">", "$reghome/response$cid.reg") || die "pofrsreg.pl Error: Cannot create the response file to register client $uuid: $! \n";
			select RESP;
			print "Status:DENIED#Client exists. Contact POFR server admin#0302";
			close(RESP);
			
			#Clean up the request and response files. The POFR client will have to send a new one, after the old DB record is dropped.
			unlink "$reghome/request$cid.luarm" or warn "pofrsreg.pl Warning: Could not remove request file request$cid.luarm after non effective registration for client $uuid: $! \n";
			
			die "pofrsreg.pl Error: Client with uuid:$uuid is ALREADY registered in the LHLT database! I cannot register this client, sorry. \n You will need to drop the database record first. \n"; 
			#$SQLh->finish();
		} elsif ( $cidhits[0]=="0") {
			#The record does not exist. We need make an account and database entry. Then SQL INSERT the data.
			#Make a random-ish user id that will upload the data for that client
			my $construid=md5_hex($cid);
			system "useradd -d $userhome/$construid $construid";
			#The account should have the scponly shell, NOT a generic login shell
			system "usermod -s /bin/scponly $construid"; 
			#Generate a secure password for that user id, although an RSA key will be used
			#for client SSH aunthentication
			my $digest=sha256_hex($cid);
			system "echo $digest | passwd --stdin $construid";
			
			#Enable RSA key authentication for the created userid from the root of the client
			mkdir "$userhome/$construid/.ssh" unless -d "$userhome/$construid/.ssh";
			open (RSA, ">>", "$userhome/$construid/.ssh/authorized_keys") || die "pofrsreg.pl Error: Cannot update the authorized keys file for user $construid to register client $uuid: $! \n";
			select RSA;
			print "$rsapk";
			close(RSA);
			#Ditto for the registrar account
			mkdir "$reghome/.ssh" unless -d "$reghome/.ssh";
			open (REGRSA, ">>", "$reghome/.ssh/authorized_keys") || die "pofrsreg.pl Error: Cannot update the authorized keys file for the registrar user to register client $uuid: $! \n";
			select REGRSA;
			print "$rsapk";
			close(REGRSA);

			select STDOUT;
			
			#Make the response file passing info back to the client
			open(RESP, ">", "$reghome/response$cid.reg") || die "pofrsreg.pl Error: Cannot create the response file to register client $uuid: $! \n";
			select RESP;
			print "Status:GRANTED#$construid#$digest";
			close(RESP);

			#Clean up the request and response files, now we are done with it
			unlink "$reghome/request$cid.luarm" or warn "pofrsreg.pl Warning: Could not remove request file request$cid.luarm after registering client $uuid: $! \n";
	
			select STDOUT;

			#Create the database name here from cid
			my $dbname=$cid;
			#The dbname will be the cid without the dashes
                        $dbname =~ s/-//g;

			my ($ryear,$rmonth,$rday,$rhour,$rmin,$rsec)=dbtimestamp();
			
			#Quote the client hostname in case there are special characters
			$clienthostname=$lhltservh->quote($clienthostname);

			my $rows=$lhltservh->do ("INSERT INTO lhltable(uuid,cid,dbname,ciduser,lastip,hostname,ryear,rmonth,rday,rhour,rmin,rsec)"
				   . "VALUES ('$uuid','$cid','$dbname','$construid','$clientipaddress',"
			   	   . "$clienthostname, '$ryear','$rmonth','$rday','$rhour','$rmin','$rsec')" );
		
			if (($rows==-1) || (!defined($rows))) {
	       		print "pofrsreg.pl Error: No records were altered. Record was not registered.\n";
       			}	
			
			$SQLh->finish();

			#If this is a new registration, we also need to create a database entry for it
			#Quick hack, roll in the SQL schema from an external file, assuming that the 
			#MySQL password is in .my.cnf

			#Get the timeref
			open(TMR, "<","/proc/uptime");
			my @timerefa=<TMR>;
			close(TMR);
			my @timerefstr=split " ", $timerefa[0];
                  	my $timeref=$timerefstr[0];
			$timeref=~ tr/'.'//d;
			open (DBC, ">", "/dev/shm/$timeref.dbcreate");
			select DBC;
			#Quote the database name to avoid SQL database creation errors
			print "CREATE DATABASE `$dbname` CHARACTER SET = 'utf8mb4' COLLATE = 'utf8mb4_unicode_ci';";
			close(DBC);
			select STDOUT;
			print "pofrsreg.pl STATUS: Created database name is: $dbname and cid is: $cid \n";
			system ("mysql < /dev/shm/$timeref.dbcreate --password=$dbpass");
			system ("mysql $dbname < itpslschema.sql --password=$dbpass");
			unlink "/dev/shm/$timeref.dbcreate";

		} #end of elsif

    
}

