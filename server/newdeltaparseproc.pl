#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.38.2/x86_64-linux -I ../pofrperl/lib/5.38.2 -I ../lib
##
use lib '../pofrperl/lib/site_perl/5.38.2';

# newdeltaparseproc.pl: A POFR server script that implements delta parsing for process, file and network events
# and populates the psinfo RDBMS table of the ITPSLschema. The script also calls mergetables.pl to create archive tables with 
# non redundant information. 

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
use feature 'unicode_strings';
use File::Slurp;
use Array::Utils qw(:all);
use Data::Dumper;
use Digest::SHA qw(sha1 sha1_hex sha256_hex);
use Digest::MD5 qw(md5 md5_hex md5_base64);
use DBI;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use DateTime;
use Parallel::ForkManager;
use POSIX;
use Sys::Hostname;
use Linux::Proc::Net::TCP;
use Linux::Proc::Net::UDP;
use Net::Nslookup;
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
use IO::File;
use List::MoreUtils qw( part );
use List::AssignRef;
use File::Copy;
use IO::Compress::Gzip;
use Geo::IP2Location;
use Sys::Hostname;
use Socket;

#Sanity checks

my @whoami=getpwuid($<);
die "parseproc.pl Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0 && $whoami[3]!=0); 


#Does the POFR server directory exists under /dev/shm/luamserver
#(necessary for the net files processing) 
if (-e "/dev/shm/pofrserver" && -d "/dev/shm/pofrserver") {
        print "newdeltaparseproc.pl: Detected /dev/shm/pofrserver dir...Starting up! \n";} else {
        print "newdeltaparseproc.pl Error: Could not detect /dev/shm/pofrserver/net dir...Fresh boot? Creating it... \n";
        mkdir "/dev/shm/pofrserver";

}

#Get the hostname of the processing server, necessary to exclude certain POFR processes from entering the DB
#and wasting space.
my $serverhostname=hostname;
my $serverip=nslookup(host => "$serverhostname", type => "A", timeout => "1");

if (! (defined $serverip)) {
  print "newdeltaparseproc.pl Error: Could not resolve the POFR server IP, so I will use Sys::Hostname to obtain it. \n";
  $serverip=inet_ntoa((gethostbyname(hostname))[4]);
}

print "newdeltaparseproc.pl: Detected IP address from primary interface is $serverip \n";

 
#Get the number of server cores to make to parallelize the whole thing a bit
my $corecount=`cat /proc/cpuinfo | grep ^processor | wc -l`;
chomp $corecount;

#SERVER ENGINE ADJUSTMENTS
#How many tarballs should we have at minimum on the user home directory before we engage the engine?
#How many tarballs should we process at maximum with each POFR server engagement?
#So minimum 8 and maximum about 1 hour worth of data. That for a heavily loaded system can be 80 tarballs.
#For less loaded systems it can be around 160 tarballs. We take the heavily loaded scenario as the best course of action.
#Number always divisible by 8.
my $engontarnum=128;
my $maxtarnum=160;

#Get the list of database userids
my @authinfo=getdbauth();
my ($dbusername,$dbname,$dbpass,$hostname);

foreach my $dbentry (@authinfo) {
	($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
	}
my $datasource="DBI:MariaDB:$dbname:$hostname";
my $lhltservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
my $SQLh=$lhltservh->prepare("SELECT ciduser FROM lhltable");
$SQLh->execute();
my @cidhits;
my @row;
while (@row=$SQLh->fetchrow_array) {
	push @cidhits, @row;
}
$SQLh->finish();
$lhltservh->disconnect;

#Not all hosts/users will need processing. Only the ones that have the proper number of .tar files 
#uploaded in the home dirs AND they do not have a .pofrthread and .merge file present. Having the
#.pofrthread file present implies an already active forked parseproc.pl thread, a .merge shows mething. In that case 
#we consider the user directory as inactive (no new data to process). 
my @activeusers;
foreach my $user (@cidhits) {
    	
    	opendir(DIR, "/home/$user") || die "parseproc Error: can't open user directory /home/$user: $!";
		my @myprocfiles = sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}#[\w]*.tar.gz/  } readdir(DIR);
		my @threadflags = glob ("/home/$user/.pofrthread*");
		my $tarnums=scalar @myprocfiles;
		my $threadfsize=scalar @threadflags;
		print "user $user:size of myprocfiles is $tarnums and of of threadflags is $threadfsize \n";
		if ($tarnums >= $engontarnum && ($threadfsize == 0) && !(-e "/home/$user/.merge")) { 
			push(@activeusers, $user);
		}		
} #End of foreach my $user (@cidhits)

#Number of jobs
my $nusers=$#activeusers+1;

#Debug 
print "Processing POFR server: $serverhostname on IP: $serverip\n Running on $corecount server cores and having $nusers active users.\n Users are: @activeusers \n";

my $pm = Parallel::ForkManager->new($nusers);
 
DATA_LOOP:
foreach my $data (@activeusers) {
  # Forks and returns the pid for the child:
  my $pid = $pm->start and next DATA_LOOP;
  #Call the mergetables script
  system "./mergetables.pl $data";
  usleep(2000000);
  #Now process the data
  procuser("$data");
 
  $pm->finish; # Terminates the child process
}
	

#Subroutines here
sub filerefprocess {
	#Processes the first file of a thread and produces the reference file
	my $fitopr=shift;
	my $thnum=shift;
	my $threadspecificpath=shift;
	my $tableprocname=shift;
        my $tablefilename=shift;
	my $ptableprocname=shift;
	my $ptablefilename=shift;
	my $ldb=shift;
	my $user=shift;
	my $hostname=shift;
	my $dbusername=shift; 
	my $dbpass=shift;

	#Debug
	if ($thnum=="1") {
		print "filerefprocess status: User $user: calling filerefprocess from thread $thnum with first file $fitopr current thread process table $tableprocname current thread file table $tablefilename \n";
		print "filerefprocess status: NOT DEFINED ptableprocname and ptablefilename as this is the FIRST THREAD \n";
	} else {
		print "filerefprocess status: User $user: calling filerefprocess from thread $thnum with first file $fitopr current thread process table $tableprocname current thread file table $tablefilename \n";
		print "filerefprocess status: User $user: NOT THE FIRST THREAD: previous thread process table $ptableprocname and previous thread file table $ptablefilename \n";
	}

	my $tzone;
        my $epochref;
        my $msecs;
        my $epochplusmsec;
	my @filedata=split '#',$fitopr;
	$epochplusmsec=$filedata[0];
        $tzone=$filedata[1];
        $tzone =~ s/.proc//;
	$msecs=substr $epochplusmsec, -6;
        $epochref=substr $epochplusmsec, 0, -6;
	#Create the reference file
	copy ("$threadspecificpath/dev/shm/$fitopr", "$threadspecificpath/dev/shm/referencefile.proc");
	#Now open and process the first file
	open(FHLZ, '<', "$threadspecificpath/dev/shm/$fitopr", '<:utf8') or die $!;
	#my $FHLZ = IO::File->new("$threadspecificpath/dev/shm/$fitopr", '<:utf8');
	undef $/;
	my $buffer=<FHLZ>;

	my @lines=split "\n", $buffer;
	#sprocpid###$proc###$ppid###$ruid###$euid###$rgid###$egid###$name###$cmdline
        my ($sprocpid,$pid,$ppid,$pruid,$peuid,$prgid,$pegid,$procname,$procarg,$procfiles);
	#Connect to the database
	my $userdb="DBI:MariaDB:$ldb:$hostname";
        my $hostservh=DBI->connect ($userdb, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});

	foreach my $line (@lines) {
		chomp $line;
		($sprocpid,$pid,$ppid,$pruid,$peuid,$prgid,$pegid,$procname,$procarg,$procfiles)=split("###", $line);
		#Debug
		#print "filerefprocess debug: sprocpid: $sprocpid\n pid:$pid \n ppid:$ppid \n procfiles: $procfiles \n";

		my @excludepid=split ',', $sprocpid;
                if ( $pid==$excludepid[0] or $pid==$excludepid[1] or $ppid==$excludepid[0] or $ppid==$excludepid[1] or $procname eq '' or ($procname eq "ssh" and $procarg =~ m/($serverhostname)/ ) or ($procname eq "scp" and $procarg =~ m/($serverhostname)/) or ($procname eq "ssh" and $procarg =~ m/($serverip)/ ) or ($procname eq "scp" and $procarg =~ m/($serverip)/) ) {
			#Here we exclude the processes that are related to POFR client, as well as erroneous
			#processes: processes that we did not manage to capture properly due to the fact they were 
			#too fast to capture and scp transfers of POFR client data. Do nothing.
		} else {
			my $digeststr1=$pid.$ppid.$pruid.$procname.$procarg;
                        my $shanorm=sha1_hex($digeststr1);
			if ($thnum==1) {
				#First thread
				my $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tableprocname WHERE shanorm='$shanorm' ");
				$SQLh->execute();
                                my @shahits=$SQLh->fetchrow_array();
				if ( $shahits[0]>="1" ) {
					#First thread and record exists in current thread. Do nothing
				} else {
					#First thread and record does not exist. Do we have in the merged psinfo table?
					$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shanorm='$shanorm' ");
					$SQLh->execute();
                                	my @psinfoshahits=$SQLh->fetchrow_array();
					if ( $psinfoshahits[0]>="1" ) {
						#First thread, record does not exist in current thread but exists in the psinfo table from a previous thread cycle of the merged window
						#Have any of the files changed since then?
						my $digeststr2=$pid.$ppid.$pruid.$procname.$procarg.$procfiles;
						my $shafull=sha1_hex($digeststr2);
						$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shafull='$shafull' AND shanorm='$shanorm' ");
						$SQLh->execute();
						my @psinfoshafullhits=$SQLh->fetchrow_array();
						if ( $psinfoshafullhits[0]>="1" ) {
							#First thread, record does not exist in current thread but exists in the psinfo table from a previous thread cycle of the merged window
							#AND files have NOT changed. Do nothing
						} else {
							#First thread, record does not exist in current thread but exists in the psinfo table from a previous thread cycle of the merged window
							#AND files HAVE changed. Insert ONLY the relevant files.
							my @procfilehits=split(" ", $procfiles);
							foreach my $pf (@procfilehits) {
								#A unique digest for each file access should be formed by a combination of the filename, uid
								#,pid and ppid as well as the process name to avoid a situation where redundant file events are
								#logged (anon_inode:[eventfd] case): if it on the SHASUM is on the filename only.
								my $sanitizedpf=sanitize_filename($pf);
                                                                my $filedigeststr2=$sanitizedpf.$pruid.$pid.$ppid.$procname;
								my $shapf=sha1_hex($filedigeststr2);
								#Since the process record exists in the psinfo table, does the file in question exist on the fileinfo OR the current threads table?
								$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM fileinfo WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
								$SQLh->execute();
                                                                my @mergedfileinfohits=$SQLh->fetchrow_array();
								$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tablefilename WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
								$SQLh->execute();
                                                                my @fileinfohits=$SQLh->fetchrow_array();
								if ( $mergedfileinfohits[0] >= "1" || $fileinfohits[0] >= "1") {
									#File exists, do nothing
								} else {
									#File is observed for the first time, insert it.
									if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) {
										#irrelevant name, throw it away 
									} else {
										my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                                                $sanitizedpf=$hostservh->quote($sanitizedpf);
                                                                                my $rows=$hostservh->do ("INSERT INTO $tablefilename(shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                                                . "VALUES ('$shapf',$sanitizedpf,'$pruid','$peuid','$prgid','$pegid','$procname','$pid','$ppid',"
                                                                                . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
									} #end of if ( ($sanitizedpf eq...

                         					} #end of if ( $mergedfileinfohits[0] >= "1" 
							} #end of foreach my $pf (@procfilehits)
						} #end of if ( $psinfoshafullhits[0]>="1" )
                                          } else {
						#First thread, record does not exist in current thread, it does also NOT exist in the psinfo table from a previous thread cycle of the merged window 
						#thus it has to be SQL inserted.
						my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                my $digeststr2=$pid.$ppid.$pruid.$procname.$procarg.$procfiles;
                                                my $shafull=sha1_hex($digeststr2);
                                                $procarg=$hostservh->quote($procarg);
                                                $procfiles=$hostservh->quote($procfiles);
                                                my $rows=$hostservh->do ("INSERT INTO $tableprocname(shanorm,shafull,ruid,euid,rgid,egid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                . "VALUES ('$shanorm','$shafull','$pruid','$peuid','$prgid','$pegid','$pid','$ppid','$procname',$procarg,"
                                                . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                if (($rows==-1) || (!defined($rows))) {
                                                        print "parseproc.pl Fatal Error: No process record was altered. Record $line was not registered.\n";
                                                }
						my $sofprocfiles=length($procfiles);
                                                if ( $sofprocfiles >= 3) {
                                                	my @pfarray=split(" ",$procfiles);
                                                        foreach my $pfile (@pfarray) {
                                                        	my $sanitizedpf=sanitize_filename($pfile);
								
                                                                if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) {
									#irrelevant name, throw it away
								} else {
									my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
									my $filedigeststr=$sanitizedpf.$pruid.$pid.$ppid.$procname;
                                                                        my $shapf=sha1_hex($filedigeststr);
									$sanitizedpf=$hostservh->quote($sanitizedpf);
                                                                        my $rows=$hostservh->do ("INSERT INTO $tablefilename(shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                                        . "VALUES ('$shapf',$sanitizedpf,'$pruid','$peuid','$prgid','$pegid','$procname','$pid','$ppid',"
                                                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                                } #end of if ( ($sanitizedpf eq...
							} #end of  foreach my $pfile
						} #end of if  $sofprocfiles >= 3)
					} #end of if ( $psinfoshahits[0]>="1" ) else ... 
				} #end of if ( $shahits[0]>="1" ) else...
			} else {
				#Not the first thread
				#Does the record exist in the merged psinfo OR the previous thread's process table?
				my $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shanorm='$shanorm' ");
				$SQLh->execute();
				my @psinfoshahits=$SQLh->fetchrow_array();
				$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $ptableprocname WHERE shanorm='$shanorm' ");
				$SQLh->execute();
				my @psinfoshahits2=$SQLh->fetchrow_array();
				if ( $psinfoshahits[0]>="1" || $psinfoshahits2[0]>="1") {
					#NOT the first thread, record exists in the psinfo table OR in the previous thread table
					#Have any of the files changed since then?
					my $digeststr2=$pid.$ppid.$pruid.$procname.$procarg.$procfiles;
                                        my $shafull=sha1_hex($digeststr2);
					$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shafull='$shafull' AND shanorm='$shanorm' ");
                                        $SQLh->execute();
					my @psinfoshafullhits=$SQLh->fetchrow_array();
					$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $ptableprocname WHERE shafull='$shafull' AND shanorm='$shanorm' ");
                                        $SQLh->execute();
					my @psinfoshafullhits2=$SQLh->fetchrow_array();
					if ( $psinfoshafullhits[0]>="1" || $psinfoshafullhits2[0]>="1" ) {
						 #NOT the first thread, record does  exists in the psinfo table OR the previous thread
						 #AND files have NOT changed. Do nothing
					} else {
						#NOT the first thread, record exists in the psinfo table OR from a previous thread
						#AND files HAVE changed. Insert ONLY the relevant files.
						my @procfilehits=split(" ", $procfiles);
						foreach my $pf (@procfilehits) {
							#A unique digest for each file access should be formed by a combination of the filename, uid
							#,pid and ppid as well as the process name to avoid a situation where redundant file events are
							#logged (anon_inode:[eventfd] case): if it on the SHASUM is on the filename only.
							my $sanitizedpf=sanitize_filename($pf);
                                                        my $filedigeststr2=$sanitizedpf.$pruid.$pid.$ppid.$procname;
                                                       	my $shapf=sha1_hex($filedigeststr2);
							#Since the process record exists in the psinfo table, does the file in question exist on the fileinfo OR on the previous thread OR on the current threads table?
							$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM fileinfo WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
                                                        $SQLh->execute();
                                                        my @mergedfileinfohits=$SQLh->fetchrow_array();
                                                        $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tablefilename WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
                                                        $SQLh->execute();
                                                        my @fileinfohits=$SQLh->fetchrow_array();
							$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $ptablefilename WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
							$SQLh->execute();
							my @previousfileinfohits=$SQLh->fetchrow_array();

							if ( $mergedfileinfohits[0] >= "1" || $fileinfohits[0] >= "1" || $previousfileinfohits[0] >= "1" ) {
								#File exists, do nothing
							} else {
								#File is observed for the first time, insert it.
								if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) {
									#irrelevant name, throw it away 
								} else {
									my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                                        $sanitizedpf=$hostservh->quote($sanitizedpf);
                                                                        my $rows=$hostservh->do ("INSERT INTO $tablefilename(shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                                        . "VALUES ('$shapf',$sanitizedpf,'$pruid','$peuid','$prgid','$pegid','$procname','$pid','$ppid',"
                                                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
								} #end of if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) else ...
							} #end of if ( $mergedfileinfohits[0] >= "1" || $fileinfohits[0] >= "1") else ...
						} #end of foreach my $pf (@procfilehits) ...
					} #end of if ( $psinfoshafullhits[0]>="1" ) else ...
				} else {
					#NOT the first thread, record does NOT exist in the psinfo table NOR on the previous thread
					#Do we by any chance have it on the current thread?
					$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tableprocname WHERE shanorm='$shanorm' ");
                                        $SQLh->execute();
					my @tableshahits=$SQLh->fetchrow_array();
					if ( $tableshahits[0]>="1" ) {
						#NOT the first thread, record does NOT exist in the psinfo table NOR a previous thread 
						#but does exist on the current thread. Files are unlikely to have changed. Do nothing
					} else {
						#NOT the first thread, record does NOT exist in the psinfo table NOR a previous thread 
						#and NOT on the current thread. Record need to be SQL inserted.
						my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                my $digeststr2=$pid.$ppid.$pruid.$procname.$procarg.$procfiles;
                                                my $shafull=sha1_hex($digeststr2);
                                                $procarg=$hostservh->quote($procarg);
                                                $procfiles=$hostservh->quote($procfiles);
                                                my $rows=$hostservh->do ("INSERT INTO $tableprocname(shanorm,shafull,ruid,euid,rgid,egid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                . "VALUES ('$shanorm','$shafull','$pruid','$peuid','$prgid','$pegid','$pid','$ppid','$procname',$procarg,"
                                                . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                if (($rows==-1) || (!defined($rows))) {
                                                        print "parseproc.pl Fatal Error: No process record was altered. Record $line was not registered.\n";
                                                }
						my $sofprocfiles=length($procfiles);
                                                if ( $sofprocfiles >= 3) {
                                                        my @pfarray=split(" ",$procfiles);
                                                        foreach my $pfile (@pfarray) {
                                                                my $sanitizedpf=sanitize_filename($pfile);
								if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) {
									#irrelevant name, throw it away
								} else {
									my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
									my $filedigeststr=$sanitizedpf.$pruid.$pid.$ppid.$procname;
                                                                        my $shapf=sha1_hex($filedigeststr);
									$sanitizedpf=$hostservh->quote($sanitizedpf);
                                                                        my $rows=$hostservh->do ("INSERT INTO $tablefilename(shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                                        . "VALUES ('$shapf',$sanitizedpf,'$pruid','$peuid','$prgid','$pegid','$procname','$pid','$ppid',"
                                                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
								} #end of if ( ($sanitizedpf eq POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) else...
							} #end of foreach my $pfile (@pfarray)
						} #end of if ( $sofprocfiles >= 3)
					} #end of if ( $ptableshahits[0]>="1" ) else ...
				} #end of if ( $psinfoshahits[0]>="1" ) else ...
			} #end of  if ($thnum==1) else 
		
		}  #end of if ( $pid==$excludepid[0] or $pid==$excludepid[1] or $pid==$excludepid[2] or $ppid==$excludepid[0] or $ppid==$excludepid[1] or $ppid==$excludepid[2] or $procname eq ''...else ...

	} #end of foreach my $line (@lines)
	
	#Here if it all goes well, we can unlink the first file. We do NOT DELETE the referencefile.proc
	unlink "$threadspecificpath/dev/shm/$fitopr" or warn "parseproc.pl Warning: Could not unlink $threadspecificpath/dev/shm/$fitopr due to: $!";
											
	#Disconnect from the host database
	$hostservh->disconnect;
} #end of filerefprocess subroutine		

sub fileothprocess {
	#Processes every other file of a thread (not the first one) and procduces a delta
	#to remove redundant (highly repetitive) data.
	my $fitopr=shift;
	my $thnum=shift;
	my $threadspecificpath=shift;
	my $tableprocname=shift;
        my $tablefilename=shift;
        my $ptableprocname=shift;
        my $ptablefilename=shift;
        my $ldb=shift;
	my $user=shift;
        my $hostname=shift;
        my $dbusername=shift;
        my $dbpass=shift;

	#Debug
	print "calling fileothprocess for user $user from thread $thnum with first file $fitopr current thread process table $tableprocname current thread file table $tablefilename \n";
	print "previous thread process table $ptableprocname and previous thread file table $ptablefilename \n";
	

	#Sanity check, do we we have the reference file?
	if ( (-e "$threadspecificpath/dev/shm/referencefile.proc")) {
		print "fileothprocess: User $user Found my reference file on thread number $thnum and path $threadspecificpath. \n";
	} else {
		die "fileothprocess: Error: USer $user Could not find my reference file on thread number $thnum and path $threadspecificpath. \n. No reference file, no delta. Exiting! \n";
	}

	#Here we produce the Delta
	#Read the current file
	open(FHLZ, '<', "$threadspecificpath/dev/shm/$fitopr", '<:utf8') or die $!;
	#my $FHLZ = IO::File->new("$threadspecificpath/dev/shm/$fitopr", '<:utf8');
        undef $/;
        my $buffer2=<FHLZ>;

        my @lines2=split "\n", $buffer2;
	
	#Read the reference file
	open(REFZ, '<', "$threadspecificpath/dev/shm/referencefile.proc", '<:utf8') or die $!;
        #my $REFZ = IO::File->new("$threadspecificpath/dev/shm/referencefile.proc", '<:utf8');
        undef $/;
        my $buffer1=<FHLZ>;

        my @lines1=split "\n", $buffer1;
	#And now we produce the Delta, which 
	my @delta = array_minus(@lines2, @lines1);
	#What is the size of the delta
	#(we are going to need that to know when to delete the reference file
	my $sizeofdelta=scalar(@delta);
	
	#From now on we work on the Delta only.
	my $tzone;
        my $epochref;
        my $msecs;
        my $epochplusmsec;
        my @filedata=split '#',$fitopr;
        $epochplusmsec=$filedata[0];
        $tzone=$filedata[1];
        $tzone =~ s/.proc//;
        $msecs=substr $epochplusmsec, -6;
        $epochref=substr $epochplusmsec, 0, -6;
	#sprocpid###$proc###$ppid###$ruid###$euid###$rgid###$egid###$name###$cmdline
        my ($sprocpid,$pid,$ppid,$pruid,$peuid,$prgid,$pegid,$procname,$procarg,$procfiles);
 	
	#Connect to the database
 	my $userdb="DBI:MariaDB:$ldb:$hostname";
 	my $hostservh=DBI->connect ($userdb, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	
	#Is this the last proc file on this thread?
	my @remainingprocs = glob ("$threadspecificpath/dev/shm/*.proc");
        my $nremainingprocs = scalar @remainingprocs;

	if ($nremainingprocs == "1") {
		#This is the last file, we need to hit the RDBMS
		foreach my $entry (@delta) {
			chomp $entry;
                	($sprocpid,$pid,$ppid,$pruid,$peuid,$prgid,$pegid,$procname,$procarg,$procfiles)=split("###", $entry);
                	my @excludepid=split ',', $sprocpid;
			if ( $pid==$excludepid[0] or $pid==$excludepid[1] or $ppid==$excludepid[0] or $ppid==$excludepid[1] or $procname eq '' or ($procname eq "ssh" and $procarg =~ m/($serverhostname)/ ) or ($procname eq "scp" and $procarg =~ m/($serverhostname)/) or ($procname eq "ssh" and $procarg =~ m/($serverip)/ ) or ($procname eq "scp" and $procarg =~ m/($serverip)/) ) {
				#Here we exclude the processes that are related to POFR client, as well as erroneous
				#processes: processes that we did not manage to capture properly due to the fact they were 
				#too fast to capture and scp transfers of POFR client data. Do nothing.
			} else {
				my $digeststr1=$pid.$ppid.$pruid.$procname.$procarg;
                        	my $shanorm=sha1_hex($digeststr1);
				if ($thnum==1) {
					#First thread
					my $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tableprocname WHERE shanorm='$shanorm' ");
                                	$SQLh->execute();
                                my @shahits=$SQLh->fetchrow_array();
                                if ( $shahits[0]>="1" ) {
					#First thread and record exists in current thread. Do nothing
				} else {
					#First thread and record does not exist. Do we have in the merged psinfo table?
					$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shanorm='$shanorm' ");
                                        $SQLh->execute();
                                        my @psinfoshahits=$SQLh->fetchrow_array();
                                        if ( $psinfoshahits[0]>="1" ) {
						#First thread, record does not exist in current thread but exists in the psinfo table from a previous thread cycle of the merged window
						#Have any of the files changed since then?
						my $digeststr2=$pid.$ppid.$pruid.$procname.$procarg.$procfiles;
                                                my $shafull=sha1_hex($digeststr2);
                                                $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shafull='$shafull' AND shanorm='$shanorm' ");
                                                $SQLh->execute();
                                                my @psinfoshafullhits=$SQLh->fetchrow_array();
                                                if ( $psinfoshafullhits[0]>="1" ) {
							#First thread, record does not exist in current thread but exists in the psinfo table from a previous thread cycle of the merged window
							#AND files have NOT changed. Do nothing
						} else {
							#First thread, record does not exist in current thread but exists in the psinfo table from a previous thread cycle of the merged window
							#AND files HAVE changed. Insert ONLY the relevant files.
							my @procfilehits=split(" ", $procfiles);
                                                        foreach my $pf (@procfilehits) {
								#A unique digest for each file access should be formed by a combination of the filename, uid
								#,pid and ppid as well as the process name to avoid a situation where redundant file events are
								#logged (anon_inode:[eventfd] case): if it on the SHASUM is on the filename only.
								my $sanitizedpf=sanitize_filename($pf);
                                                                my $filedigeststr2=$sanitizedpf.$pruid.$pid.$ppid.$procname;
                                                                my $shapf=sha1_hex($filedigeststr2);
								#Since the process record exists in the psinfo table, does the file in question exist on the fileinfo OR the current threads table?
								$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM fileinfo WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
                                                                $SQLh->execute();
                                                                my @mergedfileinfohits=$SQLh->fetchrow_array();
                                                                $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tablefilename WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
                                                                $SQLh->execute();
                                                                my @fileinfohits=$SQLh->fetchrow_array();
                                                                if ( $mergedfileinfohits[0] >= "1" || $fileinfohits[0] >= "1") {
									#File exists, do nothing
								} else {
									#File is observed for the first time, insert it.
									if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) {
										#irrelevant name, throw it away
									} else {
										my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                                                $sanitizedpf=$hostservh->quote($sanitizedpf);
                                                                                my $rows=$hostservh->do ("INSERT INTO $tablefilename(shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                                                . "VALUES ('$shapf',$sanitizedpf,'$pruid','$peuid','$prgid','$pegid','$procname','$pid','$ppid',"
                                                                                . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                                        } #end of if ( ($sanitizedpf eq...
								} #end of if ( $mergedfileinfohits[0] >= "1"
							} #end of foreach my $pf (@procfilehits)
						} #end of if ( $psinfoshafullhits[0]>="1" )
					} else {
						#First thread, record does not exist in current thread, it does also NOT exist in the psinfo table from a previous thread cycle of the merged window 
						#thus it has to be SQL inserted.
						my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                my $digeststr2=$pid.$ppid.$pruid.$procname.$procarg.$procfiles;
                                                my $shafull=sha1_hex($digeststr2);
                                                $procarg=$hostservh->quote($procarg);
                                                $procfiles=$hostservh->quote($procfiles);
                                                my $rows=$hostservh->do ("INSERT INTO $tableprocname(shanorm,shafull,ruid,euid,rgid,egid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                . "VALUES ('$shanorm','$shafull','$pruid','$peuid','$prgid','$pegid','$pid','$ppid','$procname',$procarg,"
                                                . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                if (($rows==-1) || (!defined($rows))) {
                                                        print "parseproc.pl Fatal Error: No process record was altered. Record $entry was not registered.\n";
                                                }
                                                my $sofprocfiles=length($procfiles);
                                                if ( $sofprocfiles >= 3) {
                                                        my @pfarray=split(" ",$procfiles);
                                                        foreach my $pfile (@pfarray) {
                                                                my $sanitizedpf=sanitize_filename($pfile);
                                                                if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) {
									#irrelevant name, throw it away
								} else {
									my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                                        my $filedigeststr=$sanitizedpf.$pruid.$pid.$ppid.$procname;
                                                                        my $shapf=sha1_hex($filedigeststr);
									$sanitizedpf=$hostservh->quote($sanitizedpf);
                                                                        my $rows=$hostservh->do ("INSERT INTO $tablefilename(shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                                        . "VALUES ('$shapf',$sanitizedpf,'$pruid','$peuid','$prgid','$pegid','$procname','$pid','$ppid',"
                                                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                                } #end of if ( ($sanitizedpf eq...
							} #end of  foreach my $pfile
						} #end of if  $sofprocfiles >= 3)
					} #end of if ( $psinfoshahits[0]>="1" ) else ...
				 } #end of if ( $shahits[0]>="1" ) else...
			} else {
				#Not the first thread
				#Does the record exist in the merged psinfo OR the previous thread's process table?
				my $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shanorm='$shanorm' ");
                                $SQLh->execute();
                                my @psinfoshahits=$SQLh->fetchrow_array();
				$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $ptableprocname WHERE shanorm='$shanorm' ");
                                $SQLh->execute();
                                my @psinfoshahits2=$SQLh->fetchrow_array();
                                if ( $psinfoshahits[0]>="1" || $psinfoshahits2[0]>="1" ) {
					#NOT the first thread, record exists in the psinfo table OR in the previous thread table
					#Have any of the files changed since then?
					my $digeststr2=$pid.$ppid.$pruid.$procname.$procarg.$procfiles;
                                        my $shafull=sha1_hex($digeststr2);
					$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM psinfo WHERE shafull='$shafull' AND shanorm='$shanorm' ");
                                        $SQLh->execute();
                                        my @psinfoshafullhits=$SQLh->fetchrow_array();
					$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $ptableprocname WHERE shafull='$shafull' AND shanorm='$shanorm' ");
                                        $SQLh->execute();
                                        my @psinfoshafullhits2=$SQLh->fetchrow_array();
                                        if ( $psinfoshafullhits[0]>="1" || $psinfoshafullhits2[0]>="1" ) {
						#NOT the first thread, record does  exists in the psinfo table OR the previous thread
						#AND files have NOT changed. Do nothing
					} else {
						#NOT the first thread, record exists in the psinfo table OR from a previous thread
						#AND files HAVE changed. Insert ONLY the relevant files.
						my @procfilehits=split(" ", $procfiles);
                                                foreach my $pf (@procfilehits) {
							#A unique digest for each file access should be formed by a combination of the filename, uid
                                                        #,pid and ppid as well as the process name to avoid a situation where redundant file events are
                                                        #logged (anon_inode:[eventfd] case): if it on the SHASUM is on the filename only.
                                                        my $sanitizedpf=sanitize_filename($pf);
                                                        my $filedigeststr2=$sanitizedpf.$pruid.$pid.$ppid.$procname;
                                                        my $shapf=sha1_hex($filedigeststr2);
							#Since the process record exists in the psinfo table, does the file in question exist on the fileinfo OR the current threads table?
							$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM fileinfo WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
                                                        $SQLh->execute();
                                                        my @mergedfileinfohits=$SQLh->fetchrow_array();
                                                        $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tablefilename WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
                                                        $SQLh->execute();
                                                        my @fileinfohits=$SQLh->fetchrow_array();
							$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $ptablefilename WHERE shasum='$shapf' AND pid='$pid' AND ppid='$ppid' AND ruid='$pruid' ");
                                                        $SQLh->execute();
                                                        my @previousfileinfohits=$SQLh->fetchrow_array();
                                                        if ( $mergedfileinfohits[0] >= "1" || $fileinfohits[0] >= "1" || $previousfileinfohits[0] >= "1" ) {
								#File exists, do nothing
							} else {
								#File is observed for the first time, insert it.
								if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) {
									#irrelevant name, throw it away 
								} else {
									my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                                        $sanitizedpf=$hostservh->quote($sanitizedpf);
                                                                        my $rows=$hostservh->do ("INSERT INTO $tablefilename(shasum,filename,ruid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                                        . "VALUES ('$shapf',$sanitizedpf,'$pruid','$peuid','$prgid','$pegid','$procname','$pid','$ppid',"
                                                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                                } #end of if ( ($sanitizedpf eq "PODRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) else ...
							} #end of if ( $mergedfileinfohits[0] >= "1" || $fileinfohits[0] >= "1") else ...
						} #end of foreach my $pf (@procfilehits) ...
					 } #end of if ( $psinfoshafullhits[0]>="1" ) else ...
				 } else {
					#NOT the first thread, record does NOT exist in the psinfo table NOR on the previous thread
					#Do we by any chance have it on the current thread?
					$SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tableprocname WHERE shanorm='$shanorm' ");
                                        $SQLh->execute();
					my @tableshahits=$SQLh->fetchrow_array();
                                        if ( $tableshahits[0]>="1" ) {
						#NOT the first thread, record does NOT exist in the psinfo table NOR a previous thread 
						#but does exist on the current thread. Files are unlikely to have changed. Do nothing
					} else {
						#NOT the first thread, record does NOT exist in the psinfo table NOR a previous thread 
						#and NOT on the current thread. Record needs to be SQL inserted.
						my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                my $digeststr2=$pid.$ppid.$pruid.$procname.$procarg.$procfiles;
                                                my $shafull=sha1_hex($digeststr2);
                                                $procarg=$hostservh->quote($procarg);
                                                $procfiles=$hostservh->quote($procfiles);
                                                my $rows=$hostservh->do ("INSERT INTO $tableprocname(shanorm,shafull,ruid,euid,rgid,egid,pid,ppid,command,arguments,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                . "VALUES ('$shanorm','$shafull','$pruid','$peuid','$prgid','$pegid','$pid','$ppid','$procname',$procarg,"
                                                . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                if (($rows==-1) || (!defined($rows))) {
                                                        print "parseproc.pl Fatal Error: No process record was altered. Record $entry was not registered.\n";
                                                }
                                                my $sofprocfiles=length($procfiles);
                                                if ( $sofprocfiles >= 3) {
                                                        my @pfarray=split(" ",$procfiles);
                                                        foreach my $pfile (@pfarray) {
                                                                my $sanitizedpf=sanitize_filename($pfile);
                                                                if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) {
									#Throw away
								} else {
									my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                                        my $filedigeststr=$sanitizedpf.$pruid.$pid.$ppid.$procname;
                                                                        my $shapf=sha1_hex($filedigeststr);
									$sanitizedpf=$hostservh->quote($sanitizedpf);
                                                                        my $rows=$hostservh->do ("INSERT INTO $tablefilename(shasum,filename,uid,euid,rgid,egid,command,pid,ppid,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec)"
                                                                        . "VALUES ('$shapf',$sanitizedpf,'$pruid','$peuid','$prgid','$pegid','$procname','$pid','$ppid',"
                                                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs')" );
                                                                } #end of if ( ($sanitizedpf eq "POFRv1NOOPENFILES") || ($sanitizedpf =~ /^'/) ) else...
							} #end of foreach my $pfile (@pfarray)
						} #end of if ( $sofprocfiles >= 3)
					} #end of if ( $tableshahits[0]>="1" ) else ...
				} #end of if ( $psinfoshahits[0]>="1" ) else ...
			} #end of  if ($thnum==1) else 
		}  #end of if ( $pid==$excludepid[0] or $pid==$excludepid[1] or $pid==$excludepid[2] or $ppid==$excludepid[0] or $ppid==$excludepid[1] or $ppid==$excludepid[2] or $procname eq ''...else ...
	 } #end of foreach my $line (@delta)
	 #Here if it all goes well, we can unlink the first file. We do NOT DELETE the referencefile.proc.gz
         unlink "$threadspecificpath/dev/shm/$fitopr" or warn "parseproc.pl Warning: Could not unlink $threadspecificpath/dev/shm/$fitopr due to: $!";
	
	 #Disconnect from the database
	 $hostservh->disconnect;

	} else {
	 	#We are not dealing with the last *.proc.gz file in this thread, so we just
		#update the reference file with the delta to ensure maximum efficiency
		#we do not update the RDBMS
		
		open(APPENDZ, '>>', "$threadspecificpath/dev/shm/referencefile.proc") or die $!;
	 	#my $APPENDZ = new IO::Compress::Gzip("$threadspecificpath/dev/shm/referencefile.proc", Append => 1 );
	 	foreach my $deltatoappend (@delta) {
         		APPENDZ->print("$deltatoappend \n");
	 	}
	 	close(APPENDZ);
		
		unlink "$threadspecificpath/dev/shm/$fitopr" or warn "parseproc.pl Warning: Could not unlink $threadspecificpath/dev/shm/$fitopr due to: $!";
      } #End of if ($remainingprocs == "1") { 

} #end of fileothprocess

#Were we implement the reference files for the network data
sub filerefnet {
	#Processes the first net file of a thread and produces the reference net file
        my $fitopr=shift;
        my $thnum=shift;
        my $threadspecificpath=shift;
        my $tablenetname=shift;
        my $tablefilename=shift;
	my $ftablefilename=shift;
        my $ptablenetname=shift;
        my $ptablefilename=shift;
	my $pseudoprocdir=shift;
        my $ldb=shift;
	my $user=shift;
	my $netparsedir=shift;
        my $hostname=shift;
        my $dbusername=shift;
        my $dbpass=shift;
	#Debug
        if ($thnum=="1") {
                print "filerefnet status: User $user: calling filerefnet from thread $thnum with first file $fitopr current thread net table $tablenetname current thread file table $tablefilename \n";
                print "filerefnet status: NOT DEFINED ptablenetname and ptablefilename as this is the FIRST THREAD \n";
        } else {
                print "filerefnet status: User $user: calling filerefnet from thread $thnum with first file $fitopr current thread net table $tablenetname current thread file table $tablefilename \n";
                print "filerefnet status: User $user: NOT THE FIRST THREAD: previous thread net table $ptablenetname and previous thread file table $ptablefilename \n";
        }
	
	print "filerefnet: User $user, thread $thnum: Processing file $fitopr for user $user \n";

	#Create the reference net file
        copy ("$threadspecificpath/dev/shm/$fitopr", "$threadspecificpath/dev/shm/referencefile.net");
	
	#Mow open and process the first net file
	open(FHLNETZ, '<', "$threadspecificpath/dev/shm/$fitopr", '<:utf8') or die $!;
	#my $FHLNETZ = IO::File->new("$threadspecificpath/dev/shm/$fitopr", '<:utf8');
        undef $/;
        my $contents=<FHLNETZ>;

 	#Parse the different contents (tcp4,udp4,tcp6,udp6)
	my ($sprocpid,$tcpdata,$tcpv6data,$udpdata,$udpv6data)=split("###", $contents);
	#Remove the header line that is unparseable
        $tcpdata =~ s/sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode//ig;
        $udpdata =~ s/sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode//ig;
        $tcpv6data =~ s/sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops//ig;
        $udpv6data =~ s/sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops//ig;

	my $joinedtcpdata="$tcpdata $tcpv6data";
        my $joinedudpdata="$udpdata $udpv6data";

	#Produce the pseudoprocdir files
	open my $jtcp, ">", "$pseudoprocdir/tcp" or die "parseproc.pl Error:Cannot create pseudoproc file for tcpdata. User $user processing client file $fitopr : $!";
        print $jtcp "$joinedtcpdata";
        close $jtcp;
        open my $judp, ">", "$pseudoprocdir/udp" or die "parseproc.pl Error: Cannot create pseudoproc file for udpdata. User $user processing client file $fitopr : $!";
        print $judp "$joinedudpdata";
        close $judp;
	
	#Debug
	print "newdeltaparseproc: Inside filerefnet, thread $thnum on user $user: about to call processnetfile. \n"; 
	#Process the network data
	processnetfile($fitopr,$thnum,$threadspecificpath,$tablenetname,$tablefilename,$ftablefilename,$ptablenetname,$ptablefilename,$pseudoprocdir,$ldb,$user,$netparsedir,$hostname,$dbusername,$dbpass,$sprocpid,"EMPTY",$serverip);

	print "newdeltaparseproc: Inside filerefnet, thread $thnum on user $user: Done with file $fitopr \n";

} #end of filerefnet subroutine

sub fileothnet {
	#This will produce the delta net file by looking at the deltas of the 
	#tcp v4 2. udp v4 3. tcp v6 4. udpv6 .
	my $fitopr=shift;
        my $thnum=shift;
        my $threadspecificpath=shift;
        my $tablenetname=shift;
        my $tablefilename=shift;
        my $ftablefilename=shift;
        my $ptablenetname=shift;
        my $ptablefilename=shift;
        my $pseudoprocdir=shift;
        my $ldb=shift;
        my $user=shift;
        my $netparsedir=shift;
        my $hostname=shift;
        my $dbusername=shift;
        my $dbpass=shift;

	#Sanity check, do we we have the reference file?
        if ( (-e "$threadspecificpath/dev/shm/referencefile.net")) {
      		print "fileothnet: Found my reference file on thread number $thnum and path $threadspecificpath. \n";
        } else {
                die "fileothnet: Error: Could not find my reference file on thread number $thnum and path $threadspecificpath. \n. No reference file, no delta. Exiting! \n";
        }

	#Here we produce the network delta
	print "fileothnet: Operating on file $fitopr on $user, thread number $thnum  \n";
	#Read the latest data
	open(FHLNETZ, '<', "$threadspecificpath/dev/shm/$fitopr", '<:utf8') or die $!;
        #my $FHLNETZ = IO::File->new("$threadspecificpath/dev/shm/$fitopr", '<:utf8');
        undef $/;
        my $contentsnew=<FHLNETZ>;

	#Parse the different contents (sprocpid, tcp4,udp4,tcp6,udp6)
	my ($sprocpid,$newtcpdata,$newtcpv6data,$newudpdata,$newudpv6data)=split("###", $contentsnew);
        
	#Read the reference data
	open(FHLNETZREF, '<', "$threadspecificpath/dev/shm/referencefile.net", '<:utf8') or die $!;
	#my $FHLNETZREF = IO::File->new("$threadspecificpath/dev/shm/referencefile.net", '<:utf8');
	my $contentsref=<FHLNETZREF>;

	#Parse the different contents from the network reference file
	my ($sprocpid2,$reftcpdata,$reftcpv6data,$refudpdata,$refudpv6data)=split("###", $contentsref);

	#TCP V4 DELTA
	my @newtcpdatacol=split "\n", $newtcpdata;
	my @reftcpdatacol=split "\n", $reftcpdata;
	my @deltatcpdata=array_minus(@newtcpdatacol,@reftcpdatacol);

	#TCP V6 DELTA
	my @newtcpv6datacol=split "\n", $newtcpv6data;
	my @reftcpv6datacol=split "\n", $reftcpv6data;
	my @deltatcpv6data=array_minus(@newtcpv6datacol,@reftcpv6datacol);

	#UDP V4 DELTA
	my @newudpdatacol=split "\n", $newudpdata;
	my @refudpdatacol=split "\n", $refudpdata;
	my @deltaudpdata=array_minus(@newudpdatacol,@refudpdatacol);

	#UDP V6 DELTA
	my @newudpv6datacol=split "\n", $newudpv6data;
	my @refudpv6datacol=split "\n", $refudpv6data;
	my @deltaudpv6data=array_minus(@newudpv6datacol,@refudpv6datacol);

	#And from now we work only with the deltas
	#and create the psuedoproc files for the module to pass
	my $deltatcpjoin=join("", @deltatcpdata);
	my $deltatcpv6join=join("", @deltatcpv6data);
	my $joinedtcpdata="$deltatcpjoin $deltatcpv6join";
	
	my $deltaudpjoin=join("", @deltaudpdata);
	my $deltaudpv6join=join("", @deltaudpv6data);
	my $joinedudpdata="$deltaudpjoin $deltaudpv6join";

	#Debug - Enable when you need extensive debugging but have plenty of disk space for the debug file
	#print "fileothnet: joinedtcpdata: @deltatcpdata \n @deltatcpv6data \n";
	#print "fileothnet: joinedudpdata: @deltaudpdata \n @deltaudpv6data \n";

	open my $jtcp, ">", "$pseudoprocdir/tcp" or die "newdeltaparseproc.pl Error: Inside fileothnet: User $user, thread $thnum: Cannot create pseudoproc file for tcpdata. User $user processing client file $fitopr : $!";
        print $jtcp "$joinedtcpdata";
        close $jtcp;
        open my $judp, ">", "$pseudoprocdir/udp" or die "newdeltaparseproc.pl Error:Inside fileothnet: User $user, thread $thnum: Cannot create pseudoproc file for udpdata. User $user processing client file $fitopr : $!";
        print $judp "$joinedudpdata";
        close $judp;

	#Debug
        print "newdeltaparseproc: Inside fileothnet, thread $thnum on user $user: about to call processnetfile. \n";

	#Process the network data
        processnetfile($fitopr,$thnum,$threadspecificpath,$tablenetname,$tablefilename,$ftablefilename,$ptablenetname,$ptablefilename,$pseudoprocdir,$ldb,$user,$netparsedir,$hostname,$dbusername,$dbpass,$sprocpid,$sprocpid2,$serverip);

	print "newdeltaparseproc: Inside fileothnet, thread $thnum on user $user: Done with file $fitopr \n";

}#End of fileothnet subroutine


sub procuser {
	my $user= shift;
	#Debug
	print "Processing user $user \n";

	opendir(DIR, "/home/$user") || die "parseproc Error: can't open user directory /home/$user to fetch the proc files : $!";
	
	#Get the number of files to determine how they are going to split amongst 8 cores per user
	my @mytarballs = sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}#[\w]*.tar.gz/ } readdir(DIR);
	my @toproctarballs;
	#Do we have more than $maxtarnum
	if (scalar @mytarballs > $maxtarnum) {
		#Slice at maximum length
		@toproctarballs=@mytarballs[0..$maxtarnum-1];
	} else {
		#Slice at the actual size of the original array
		@toproctarballs=@mytarballs[0..$#mytarballs];
	}

	my $tarballnum = $#toproctarballs+1;
	my $jobstoforkpercore;
	my $i=0;
	my (@tar1,@tar2,@tar3,@tar4,@tar5,@tar6,@tar7,@tar8,@tar9,@tar10,@tar11,@tar12,@tar13,@tar14,@tar15,@tar16,@tar17,@tar18,@tar19,@tar20,@tar21,@tar22,@tar23,@tar24,@tar25,@tar26,@tar27,@tar28,@tar29,@tar30,@tar31,@tar32);
	if ($tarballnum < $engontarnum ) {
		$jobstoforkpercore = 0; } else {
		$jobstoforkpercore = int ($tarballnum/32);
		( 
			deref(@tar1),
			deref(@tar2),
			deref(@tar3),
			deref(@tar4),
			deref(@tar5),
			deref(@tar6),
			deref(@tar7),
			deref(@tar8),
			deref(@tar9),
			deref(@tar10),
			deref(@tar11),
			deref(@tar12),
			deref(@tar13),
			deref(@tar14),
			deref(@tar15),
			deref(@tar16),
			deref(@tar17),
                        deref(@tar18),
                        deref(@tar19),
                        deref(@tar20),
                        deref(@tar21),
                        deref(@tar22),
                        deref(@tar23),
                        deref(@tar24),
                        deref(@tar25),
                        deref(@tar26),
                        deref(@tar27),
                        deref(@tar28),
                        deref(@tar29),
                        deref(@tar30),
                        deref(@tar31),
                        deref(@tar32),

		) = part { int($i++/$jobstoforkpercore) } @toproctarballs;
	}

 
	#Debug
	print "User $user:Detected $tarballnum tarballs and thus $jobstoforkpercore jobs to fork per core. \n Tar1 array is : @tar1 \n\nTar2 array is : @tar2 \n\nTar3 array is : @tar3 \n\n .......\n Tar32 array is: @tar32 \n\n";
	
	if ( $jobstoforkpercore==0 ) {
		die "newdeltaparseproc.pl: We do not have enough tarballs to start processing and keep all the cores busy. Will try again later \n";
	} else { 
		
		my $pm1 = Parallel::ForkManager->new(32);

		my $reftar1=\@tar1;
 		my $reftar2=\@tar2;
		my $reftar3=\@tar3;
		my $reftar4=\@tar4;
		my $reftar5=\@tar5;
		my $reftar6=\@tar6;
		my $reftar7=\@tar7;
		my $reftar8=\@tar8;
		my $reftar9=\@tar9;
        	my $reftar10=\@tar10;
        	my $reftar11=\@tar11;
        	my $reftar12=\@tar12;
        	my $reftar13=\@tar13;
        	my $reftar14=\@tar14;
        	my $reftar15=\@tar15;
        	my $reftar16=\@tar16;
		my $reftar17=\@tar17;
        	my $reftar18=\@tar18;
        	my $reftar19=\@tar19;
        	my $reftar20=\@tar20;
        	my $reftar21=\@tar21;
        	my $reftar22=\@tar22;
        	my $reftar23=\@tar23;
        	my $reftar24=\@tar24;
        	my $reftar25=\@tar25;
        	my $reftar26=\@tar26;
        	my $reftar27=\@tar27;
        	my $reftar28=\@tar28;
        	my $reftar29=\@tar29;
        	my $reftar30=\@tar30;
        	my $reftar31=\@tar31;
        	my $reftar32=\@tar32;
	
	
		DATA_LOOP:
		foreach my $r ($reftar1,$reftar2,$reftar3,$reftar4,$reftar5,$reftar6,$reftar7,$reftar8,$reftar9,$reftar10,$reftar11,$reftar12,$reftar13,$reftar14,$reftar15,$reftar16,$reftar17,$reftar18,$reftar19,$reftar20,$reftar21,$reftar22,$reftar23,$reftar24,$reftar25,$reftar26,$reftar27,$reftar28,$reftar29,$reftar30,$reftar31,$reftar32) {
  			# Forks and returns the pid for the child:
  	        	my $pid = $pm1->start and next DATA_LOOP;
			#Pass the array by reference
                	parsefiles($user,$r);
  	   		$pm1->finish; # Terminates the child process
         	}
  	
	} #end of if ( $jobstoforkpercore==0 ) else ...

} #end of sub procuser

sub parsefiles {
	my $user=shift;
	my $tarballref=shift;

	my $threadbasepath;
	my $threadspecificpath;
	print "Calling parsefiles with user $user and tarballs:  @{$tarballref}  \n";
	
	#Get the timeref
	open(TMR, "<","/proc/uptime");
	my @timerefa=<TMR>;
	close(TMR);
	my @timerefstr=split " ", $timerefa[0];
	my $timeref=$timerefstr[0];
	$timeref=~ tr/'.'//d;
	#Raise the processing flag to mark to forked procuser procs that they
	#should not touch this directory until we are done.
	my $pspid="$$";
	open(my $procflagfh, ">" ,"/home/$user/.pofrthread$timeref$pspid") or die "parseproc.pl Error: Could not open the .procflag file for writing due to: $!";
	print $procflagfh "$pspid";
	close $procflagfh;
		
	#Make the per core dirs if they do not exist.
	if (!(-e "/home/$user/proc" && "/home/$user/proc")) {
		mkdir "/home/$user/proc" or warn "Parseproc.pl Error: Cannot create proc directory entry for user $user. Full disk or other I/O issue? : $! \n";
		$threadbasepath="/home/$user/proc"; 
		} else {
		$threadbasepath="/home/$user/proc";
		}

	#Now make the thread/fork/core specific subdirectory - Which thread/core/form am I?
	#Make the dirname from the convention firsttarballtimestamp-lasttarballtimestamp.
	my ($firststamp,$firsttz,$firstsha)=split(/#/,@{$tarballref}[0]);
	my ($laststamp,$lasttz,$lastsha)=split(/#/, @{$tarballref}[-1]);
	
	#Mark the day of the first data. We should handle data within the remaining hours of the day
	#only! Each MERGE table should not have data beyond a 24 hour period for performance purposes.
	#See the foreach my $tarfile loop below.
	my ($markyear,$markmonth,$markday,$markhour,$markmin,$marksec)=timestamp($firststamp,$firsttz);

	#The threadspecificpath should have the name convention: /home/$user/proc/$firststamp-$laststamp 
	#print "First tarball has timestamp is: $firststamp. Last file has timestamp: $laststamp. \n"; 
	if (!(-e "/home/$user/proc/$firststamp-$laststamp" && "/home/$user/proc/$firststamp-$laststamp")) {
		mkdir "/home/$user/proc/$firststamp-$laststamp" or die "newdeltaparseproc.pl Error: Inside parsefiles subroutine: Cannot create thread specific proc subdirectory entry /home/$user/proc/$firststamp-$laststamp for user $user. Full disk or other I/O issue?\n";
		$threadspecificpath="/home/$user/proc/$firststamp-$laststamp"; 
	} else {
		$threadspecificpath="/home/$user/proc/$firststamp-$laststamp";
	}

	#The thread needs to become aware now on whether it has a previous one that should be checked, so that the we facilitate
        #the data reduction process: Whatever process or file record existing in the current table or the respective tables of the previous thread
        #should not be SQL inserted, based on the shasum info.
	my($previousfirststamp,$previouslaststamp,$thnumber,$ftfts,$ftlts)=determinepreviousthread("$user","$firststamp");

	#Renaming the orifinal .pofrthread lock file to make it thread number specific, helps debugging
	rename("/home/$user/.pofrthread$timeref$pspid", "/home/$user/.pofrthread$timeref$pspid"."isthreadnumber$thnumber") || die ( "newdeltaparseproc.pl Error: Could not rename thread flag /home/$user/.pofrthread$timeref$pspid as /home/$user/.pofrthread$timeref$pspid"."isthreadnumber$thnumber" );

	my $ptablenetname;
	my $ptablefilename;
	my $ptableprocname;
	my $ftablenetname;
	my $ftablefilename;
	my $ftableprocname;

	if ($previousfirststamp eq "none" && $previouslaststamp eq "none") {
		#No need to define a previous thread, we are the first thread.
		} else {
		$ptablenetname="netinfo$previousfirststamp$previouslaststamp";
		$ptablefilename="fileinfo$previousfirststamp$previouslaststamp";
		$ptableprocname="psinfo$previousfirststamp$previouslaststamp";
		$ftablenetname="netinfo$ftfts$ftlts";
		$ftablefilename="fileinfo$ftfts$ftlts";
		$ftableprocname="psinfo$ftfts$ftlts";
		
	} #End of if $previousfirststamp eq "none" 


	#Now start checking the integrity of the tarballs and move them to the proper thread subdirs for processing
	foreach my $tarfile (@$tarballref) {
		my ($timestamp,$tz,$sha)=split(/#/,$tarfile);
		#print "timestamp:$timestamp, tz:$tz, SHA:$sha \n";
		my $shaonname=substr($sha,0,-4);
		#Is the SHA256 hash of the tarball OK?
		my $shahash = Digest::SHA->new(256);
        	$shahash->addfile("/home/$user/$tarfile");
		my $digest = $shahash->hexdigest;
		if ($digest eq $shaonname ) {
			#Tarball is good, move it to the right place and untar
			#print "Tarball is good. Name SHA is $shaonname and calculated SHA is $digest . \n";
			my ($taryear,$tarmonth,$tarday,$tarhour,$tarmin,$tarsec)=timestamp($firststamp,$firsttz);
			move "/home/$user/$tarfile", "$threadspecificpath/$tarfile";
			opendir(DIR, "$threadspecificpath") || die "parseproc Error: can't open thread directory /home/$user to fetch the proc files : $!";
			my @tountarfiles= sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}#[\w]*.tar.gz/ } readdir(DIR);
			foreach my $tountar (@tountarfiles) {
				#system "tar xvf $threadspecificpath/$tountar -C $threadspecificpath";
				system "tar xvfz $threadspecificpath/$tountar -C $threadspecificpath > /dev/null 2>&1";
				unlink "$threadspecificpath/$tountar";
			} #end of foreach my $tountar

		} elsif ($digest eq "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
			#Here we have probably an empty file (0 bytes) encoded at the client
			#the sha256sum of a null input is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
			#so we discard
			print "Thread $thnumber for user $user: Tarball is not corrupt but file was sent empty from the client. Thrown in the bin.\n";
			unlink "/home/$user/$tarfile";
		} else {
			#Here we have a mismatch between the SHA on the name and the calculated one on a non empty file. File is corrupt file and needs to be deleted.
			print "Thread $thnumber for user $user: Tarball is corrupt. Name SHA is $shaonname and calculated SHA is $digest. Thrown in the bin.\n";
			unlink "/home/$user/$tarfile";
		}
		
	} #End of foreach my $tarfile


	
	opendir(DIRTHREADPROC, "$threadspecificpath/dev/shm") || die "parseproc Error: can't open thread directory $threadspecificpath/dev/shm to fetch the proc files : $!";
	opendir(DIRTHREADNET, "$threadspecificpath/dev/shm") || die "parseproc Error: can't open thread directory $threadspecificpath/dev/shm to fetch the net files : $!";
	my @myprocfiles = sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}.proc/  } readdir(DIRTHREADPROC);
	my @mynetfiles= sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}.net/  } readdir(DIRTHREADNET);
	#Did we have a bunch of empty files corrupt files? If yes, we need to cleanup and terminate early
	#to ensure that we do not leave hanging threads
	if ( !@myprocfiles ) {
		rmdir "/home/$user/proc/$firststamp-$laststamp/dev/shm" or warn "newdeltaparseproc.pl Warning: Thread $thnumber on user $user: Could not unlink the thread specific directory $threadspecificpath/dev/shm: $!";
		rmdir "/home/$user/proc/$firststamp-$laststamp/dev" or warn "newdeltaparseproc.pl Warning: Thread $thnumber on user $user: Could not unlink the thread specific directory $threadspecificpath/dev: $!";
		rmdir "/home/$user/proc/$firststamp-$laststamp" or warn "newdeltaparseproc.pl Warning: Thread $thnumber on user $user: Could not unlink the thread specific directory $threadspecificpath: $!";
		unlink "/home/$user/.pofrthread$timeref$pspid"."isthreadnumber$thnumber" or warn "newdeltaparseproc.pl Warning: Thread $thnumber on user $user: Could not unlink the .pofrthread file for user $user due to: $!";
		die "newdeltaparseproc.pl Error: Inside parsefiles subroutine: THREAD NUMBER $thnumber for user $user: Totally empty files means that we have to exit and clean up early. \n";
	}

	#my @sorted_numbers = sort @myprocfiles;
	#Debug
	#print "myprocfiles array is: @myprocfiles \n";
	  
	#If there are are new files, hit the LHLT db to find the dbname for that user
	my ($dbusername,$dbname,$dbpass,$hostname);
	foreach my $dbentry (@authinfo) {
		($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
	}
	my $datasource="DBI:MariaDB:$dbname:$hostname";
	my $lhltservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	my $SQLh=$lhltservh->prepare("SELECT cid FROM lhltable WHERE ciduser='$user' ");
	$SQLh->execute();
	my @dbnamehits=$SQLh->fetchrow_array();
	$SQLh->finish();
	$lhltservh->disconnect;
	my $ldb=$dbnamehits[0];
	#Remove the "-" from the dbname
	$ldb =~ s/-//g;
	print "Dbname is $ldb \n";
	
	#Connect to the right host db
	my $userdb="DBI:MariaDB:$ldb:$hostname";
	my $hostservh=DBI->connect ($userdb, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});	
	#Ensure that we are on the proper character set
	$hostservh->do('SET NAMES utf8mb4');
	
	#Now make the per thread specific tables (note: make sure that the SQL table creation code here is in sync
	#with the server/itpslschema.sql table definitions. They should NOT be different!)
	my $tablenetname="netinfo$firststamp$laststamp";
	my $tablefilename="fileinfo$firststamp$laststamp";
	my $tableprocname="psinfo$firststamp$laststamp";

	my @sqltca= (
		"DROP TABLE IF EXISTS `$tablenetname`;",

		 "CREATE TABLE `$tablenetname` (
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
		) ENGINE=MyISAM CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",

		"DROP TABLE IF EXISTS `$tablefilename`;",

		"CREATE TABLE `$tablefilename` (
  			`fileaccessid` bigint NOT NULL AUTO_INCREMENT,
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
			) ENGINE=MyISAM AUTO_INCREMENT=246450 CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",
		
		"DROP TABLE IF EXISTS `$tableprocname`;",

		"CREATE TABLE `$tableprocname` (
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
  			PRIMARY KEY (`psentity`)
		) ENGINE=MyISAM AUTO_INCREMENT=19470 CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"

		#"SELECT SLEEP(40);"

	); #end of @tca

	for my $sqlst (@sqltca) {
		print "newdeltaparseproc.pl Info: Inside parsefiles soubroutine: THREAD NUMBER $thnumber : Creating tables $tableprocname, $tablefilename, $tablenetname . \n";
		$hostservh->do($sqlst);
	}
		
	#close the DBI handle the created the initial thread tables
	$hostservh->disconnect;
	
	#Make the proper directory to be able to execute parsenet.pl in parallel
	#to increase efficiency
	my $pseudoprocdir;
        my $netparsedir;
	
	#Are we the first thread?
	if ( $thnumber==1) {
		#If yes, make the user dirs (if they do not exist) and also your own thread specific subdirs as required
		if (!(-e "/dev/shm/pofrserver/$user" && "/dev/shm/pofrserver/$user")) {
			mkdir "/dev/shm/pofrserver/$user" or die "newdeltaparseproc.pl Error: THREAD NUMBER 1 FIRST TIME: Cannot create user $user directory under /dev/shm/pofrserver. Full memory or other I/O issue?: $! \n";
			mkdir "/dev/shm/pofrserver/$user/net" or die "newdeltaparseproc.pl Error: THREAD NUMBER 1 FIRST TIME: Cannot create user $user/net directory under /dev/shm/pofrserver. Full memory or other I/O issue?: $!\n"; 
			print "newdeltaparseproc.pl Info: Inside parsefiles subroutine: Thread 1: made the /dev/shm/ user dirs, about to go to sleep for 3 secs. \n";
			usleep(20000000);
			print "newdeltaparseproc.pl Info: Inside parsefiles subroutine: Thread 1: Waking up from a 3 sec sleep, and about to make the thread 1 subdir for the first time. \n"; 
			mkdir "/dev/shm/pofrserver/$user/$firststamp-$laststamp" or die "newdeltaparseproc.pl Error: Inside parsefiles subroutine: THREAD NUMBER 1 (is really $thnumber) FIRST TIME: Cannot create user $user/$firststamp-$laststamp directory under /dev/shm/pofrserver. Full memory or other I/O issue? : $! \n";
                mkdir "/dev/shm/pofrserver/$user/$firststamp-$laststamp/net" or die "newdeltaparseproc.pl Error: Inside parsefiles subroutine: THREAD NUMBER 1 FIRST TIME: Cannot create user $user/$firststamp-$laststamp/net directory under /dev/shm/pofrserver. Full memory or other I/O issue?: $! \n";
			$pseudoprocdir="/dev/shm/pofrserver/$user/$firststamp-$laststamp/net";
			$netparsedir="/dev/shm/pofrserver/$user/$firststamp-$laststamp";
		} else {
 			#Otherwise as thread 1 make only your thread specific  subdirs (the next time thread 1 is invoked after the first time)
 			mkdir "/dev/shm/pofrserver/$user/$firststamp-$laststamp" or die "newdeltaparseproc.pl Error: Inside parsefiles subroutine: THREAD NUMBER 1: Cannot create user $user/$firststamp-$laststamp directory under /dev/shm/pofrserver. Full memory or other I/O issue?: $! \n";
                	mkdir "/dev/shm/pofrserver/$user/$firststamp-$laststamp/net" or die "newdeltaparseproc.pl Error: Inside parsefiles subroutine: THREAD NUMBER 1: Cannot create user $user/$firststamp-$laststamp/net directory under /dev/shm/pofrserver. Full memory or other I/O issue?: $! \n";
			$pseudoprocdir="/dev/shm/pofrserver/$user/$firststamp-$laststamp/net";
			$netparsedir="/dev/shm/pofrserver/$user/$firststamp-$laststamp";

		} #end of if (!(-e "/dev/shm/pofrserver/$user" && "/dev/shm/pofrserver/$user"))	
		
	} else {
		#Here we are not the first thread, thus we are going to make only the thread subdirs.
		#All other threads sleep for 4 secs.
		usleep(40000000);
		if (!(-e "/dev/shm/pofrserver/$user/$firststamp-$laststamp" && "/dev/shm/pofrserver/$user/")) {
                        mkdir "/dev/shm/pofrserver/$user/$firststamp-$laststamp" or die "newdeltaparseproc.pl Error: Inside parsefiles subroutine: THREAD NUMBER $thnumber: Cannot create user $user/$firststamp-$laststamp directory under /dev/shm/pofrserver. Full memory or other I/O issue? : $!\n";
                }

                if (!(-e "/dev/shm/pofrserver/$user/$firststamp-$laststamp/net" && "/dev/shm/pofrserver/$user/net")) {
                        mkdir "/dev/shm/pofrserver/$user/$firststamp-$laststamp/net" or die "newdeltaparseproc.pl Error: THREAD NUMBER $thnumber: Cannot create user $user/$firststamp-$laststamp/net directory under /dev/shm/pofrserver. Full memory or other I/O issue? : $!\n";
                }

		$pseudoprocdir="/dev/shm/pofrserver/$user/$firststamp-$laststamp/net";
                $netparsedir="/dev/shm/pofrserver/$user/$firststamp-$laststamp";
	} #enf of if ( $thnumber==1) else...

	 
	#Here based on the which thread number are we, we wait for a certain number of seconds
	#to give the chance of a previous thread to catch up, based on the what the determinepreviousthread
	#function returns. This is necessary for the inter thread data reduction process.
	if ( $thnumber==32) {
		print "Thread no. 32, on $user sleeping for 775 secs. \n";
                usleep(775000000); } elsif ($thnumber==31) {
		print "Thread no. 31, on $user sleeping for 750 secs. \n";
                usleep(750000000); } elsif ($thnumber==30) {
		print "Thread no. 30, on $user sleeping for 720 secs. \n";
                usleep(720000000); } elsif ($thnumber==29) {
		print "Thread no. 29, on $user sleeping for 700 secs. \n";
                usleep(700000000); } elsif ($thnumber==28) {
		print "Thread no. 28, on $user sleeping for 675 secs. \n";
                usleep(675000000); } elsif ($thnumber==27) {
		print "Thread no. 27, on $user sleeping for 650 secs. \n";
                usleep(650000000); } elsif ($thnumber==26) {
		print "Thread no. 26, on $user sleeping for 625 secs. \n";
                usleep(625000000); } elsif ($thnumber==25) {
		print "Thread no. 25, on $user sleeping for 600 secs. \n";
                usleep(600000000); } elsif ($thnumber==24) {
		print "Thread no. 24, on $user sleeping for 575 secs. \n";
                usleep(575000000); } elsif ($thnumber==23) {
		print "Thread no. 23, on $user sleeping for 550 secs. \n";
                usleep(550000000); } elsif ($thnumber==22) {
		print "Thread no. 22, on $user sleeping for 525 secs. \n";
                usleep(525000000); } elsif ($thnumber==21) {
		print "Thread no. 21, on $user sleeping for 500 secs. \n";
                usleep(500000000); } elsif ($thnumber==20) {
		print "Thread no. 20, on $user sleeping for 475 secs. \n";
                usleep(475000000); } elsif ($thnumber==19) {
		print "Thread no. 19, on $user sleeping for 450 secs. \n";
                usleep(450000000); } elsif ($thnumber==18) {
		print "Thread no. 18, on $user sleeping for 425 secs. \n";
                usleep(425000000); } elsif ($thnumber==17) {
		print "Thread no. 17, on $user sleeping for 400 secs. \n";
                usleep(400000000); } elsif ($thnumber==16) {
		print "Thread no. 16, on $user sleeping for 375 secs. \n";
                usleep(375000000); } elsif ($thnumber==15) { 
		print "Thread no. 15, on $user sleeping for 350 secs. \n";
                usleep(350000000); } elsif ($thnumber==14) {
		print "Thread no. 14, on $user sleeping for 325 secs. \n";
                usleep(325000000); } elsif ($thnumber==13) {
		print "Thread no. 13, on $user sleeping for 300 secs. \n";
                usleep(300000000); } elsif ($thnumber==12) {
		print "Thread no. 12, on $user sleeping for 275 secs. \n";
                usleep(275000000); } elsif ($thnumber==11) { 
		print "Thread no. 11, on $user sleeping for 250 secs. \n";
		usleep(250000000); } elsif ($thnumber==10) {
		print "Thread no. 10, on $user sleeping for 225 secs. \n";
		usleep(225000000); } elsif ($thnumber==9) {
		print "Thread no. 9, on $user sleeping for 200 secs. \n";
		usleep(200000000); } elsif ($thnumber==8) {
		print "Thread no. 8, on $user sleeping for 175 secs. \n";
		usleep(175000000); } elsif ($thnumber==7) {
		print "Thread no. 7, on $user sleeping for 150 secs. \n";
		usleep(150000000); } elsif ($thnumber==6) {
		print "Thread no. 6, on $user sleeping for 125 secs. \n";
		usleep(125000000); } elsif ($thnumber==5) {
		print "Thread no. 5, on $user sleeping for 100 secs. \n";
		usleep(100000000); } elsif ($thnumber==4) {
		print "Thread no. 4, on $user sleeping for 75 secs. \n";
		usleep(75000000); } elsif ($thnumber==3) {
		print "Thread no. 3, on $user sleeping for 50 secs. \n";
		usleep(50000000); } elsif ($thnumber==2) {
		print "Thread no. 2, on $user sleeping for 25 secs. \n";
		usleep(25000000); } else {
		print "Thread no. 1, on $user proceeding. \n";
 		}
	
	print "newdeltaparseproc.pl Info: Inside parsefiles subroutine: Thread number $thnumber on $user is resuming from sleeping. \n";
	#Start the process parsing entries
	#Shift the first process file of the thread This is going to be the process reference file for the delta.
	my $fref=shift (@myprocfiles);
	filerefprocess($fref,$thnumber,$threadspecificpath,$tableprocname,$tablefilename,$ptableprocname,$ptablefilename,$ldb,$user,$hostname,$dbusername,$dbpass);
	 
	#Then remaining netfiles to be counted (that's why we start counting from 1 not 0)
	my $netfcounter=1;
	my $threaddirremvindex=scalar @mynetfiles;
	print "Inside parsefiles: Thread $thnumber: The threaddirremvindex size is: $threaddirremvindex \n";

	#For the rest of the files process them  with the delta function inside the fileothprocess 
	foreach my $fitopr (@myprocfiles) {
		fileothprocess($fitopr,$thnumber,$threadspecificpath,$tableprocname,$tablefilename,$ptableprocname,$ptablefilename,$ldb,$user,$hostname,$dbusername,$dbpass);
	} #end of my $fitopr (@myprocfiles)


	#Start parsing the network entries.
        #Shift the first process file of the thread This is going to be the network reference file for the delta.
	my $nref=shift (@mynetfiles);
	filerefnet($nref,$thnumber,$threadspecificpath,$tablenetname,$tablefilename,$ftablefilename,$ptablenetname,$ptablefilename,$pseudoprocdir,$ldb,$user,$netparsedir,$hostname,$dbusername,$dbpass);

	foreach my $fitopr (@mynetfiles) {
		fileothnet($fitopr,$thnumber,$threadspecificpath,$tablenetname,$tablefilename,$ftablefilename,$ptablenetname,$ptablefilename,$pseudoprocdir,$ldb,$user,$netparsedir,$hostname,$dbusername,$dbpass);
		$netfcounter=$netfcounter+1;
		print "Inside parsefiles: Thread $thnumber: Inside the mynetfiles loop netfcounter is $netfcounter while threaddirremvindex is $threaddirremvindex \n";
	}
	
	if ($netfcounter == $threaddirremvindex ) {
        	#The very last thing we do inside the per thread  context is to cleanup the thread specific directories
                #from home dirs and RAM (/dev/shm). We do not do something like an rmdir $threadspecificpath, in case
                #something resets the $threadspecificpath variable and we end up deleting root dirs. We do this gradually
                #as we do not like living dangerously. We start with the reference files.
                unlink "/home/$user/proc/$firststamp-$laststamp/dev/shm/referencefile.proc" or warn "newdeltaparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the reference file: referencefile.proc in the the thread specific directory $threadspecificpath: $!";
		unlink "/home/$user/proc/$firststamp-$laststamp/dev/shm/referencefile.net" or warn "newdeltaparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the reference file: referencefile.net in the the thread specific directory $threadspecificpath: $!";
                rmdir "/home/$user/proc/$firststamp-$laststamp/dev/shm" or warn "newdeltaparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the thread specific directory $threadspecificpath/dev/shm: $!";
                rmdir "/home/$user/proc/$firststamp-$laststamp/dev" or warn "newdeltaparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the thread specific directory $threadspecificpath/dev: $!";
                rmdir "/home/$user/proc/$firststamp-$laststamp" or warn "newdeltaparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the thread specific directory $threadspecificpath: $!";
                unlink "/dev/shm/pofrserver/$user/$firststamp-$laststamp/net/tcp" or warn "newdeltaparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the thread specific file /dev/shm/pofrserver/$user/$firststamp-$laststamp/net/tcp  : $!";
                unlink "/dev/shm/pofrserver/$user/$firststamp-$laststamp/net/udp" or warn "newdeltaparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the thread specific file /dev/shm/pofrserver/$user/$firststamp-$laststamp/net/udp  : $!";
                rmdir "/dev/shm/pofrserver/$user/$firststamp-$laststamp/net" or warn "newdelraparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the thread specific directory /dev/shm/pofrserver/$user/$firststamp-$laststamp/net under the thread specific path $threadspecificpath : $!";
                rmdir "/dev/shm/pofrserver/$user/$firststamp-$laststamp" or warn "newdeltaparseproc.pl Warning: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the thread specific directory /dev/shm/pofrserver/$user/$firststamp-$laststamp under the thread specific path $threadspecificpath : $!";

	}

	#And finally we are done by removing the .pofrthread file to signal that the dir is ready for another procparse.pl process
	#to start processing data again.
	unlink "/home/$user/.pofrthread$timeref$pspid"."isthreadnumber$thnumber" or die "newdeltaparseproc.pl Error: Inside the parsefiles subroutine: THREAD NUMBER $thnumber: Could not unlink the .pofrthread file /home/$user/.pofrthread$timeref$pspid"."isthreadnumber$thnumber for user $user due to: $!";

	
} #end of sub parsefiles
