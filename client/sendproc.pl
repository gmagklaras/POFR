#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.38.2/x86_64-linux -I ../pofrperl/lib/5.38.2
#
use lib '../pofrperl/lib/site_perl/5.38.2';

#sendproc.pl: This scripts sends/pushes securely the POFR client data to the server via SSH/SCP
#(C) Georgios Magklaras -- Steelcyber Scientific

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

use Net::OpenSSH;
use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use Archive::Tar;
use POSIX;
use Digest::SHA qw(sha256_hex sha256);
use IO::Compress::Gzip qw(gzip $GzipError);

my $completiondelay=300000;
my $initialdatabuildwait=128000000;
my $samplingloopdatabuildwait=45000000;
my $pspid="$$";

#Max number of files to send in each tarball 
my $procfilestosendatonce="384";
my $netfilestosendatonce="384";

my $nodealhits=0;
#240 seconds (4 minutes) grace time when detecting bad connections
my $postponetime=240000000;

#Some essential sanity checks
#Does the POFR clientauthentication file exist?
die "sendproc.pl Error: I cannot start because I cannot find the POFR client authentication file.\n Has the POFR client being registered with pofrcreg.pl? \n" if (!(-e "./.lcaf.dat"));

#Open the authentication file and get the credentials
open(AUTH, "<","./.lcaf.dat");
my $authdata=<AUTH>;
close(AUTH);
my @authdata=split "#",$authdata;
my $status=shift @authdata;
my $username=shift @authdata;
my $password=shift @authdata;
my @serverdata=split ":",$status;
my $s1=shift @serverdata;
my $server=shift @serverdata;

#Is there a .sendpid file?
if (-e ".sendpid") {

        die "sendproc.pl Error: Found a .sendpid file. This means that it is either a sendproc.pl process running OR this is a stale file. In the latter case, please check first and if necessary remove the stale .sendpid file and try again. \n";

} else {

        open(my $sendfh, ">" ,".sendpid") or die "sendproc.pl Error: Could not open the .sendpid file for writing due to: $!";
        print $sendfh "$pspid";
        close $sendfh;
}

my @crashleftovertarballs;
my @sampledprocfiles;
my @samplednetfiles;
my @previterationtarballs;
my @ftpscp;
my @ftpscpnet;

# Initial Wait for the data set to build up
usleep($initialdatabuildwait);

#Before we start the loop and especially when we connect for the first time to the POFR server,
#we need to ensure that the POFR server's public SSH key is in the /root/.ssh/known_hosts file.
#For that, we need to connect once without the StrictHostKeyChecking=no option. Within the 
#sampling loop, we check for the key to ensure it will not send data if they key changes.
my $firstssh = Net::OpenSSH->new($server, user => $username, password => $password, master_opts => [-o => "StrictHostKeyChecking=no"] );
if ($firstssh->error == 0 && $nodealhits < 3 ) {
	sendfiles($server,$username,$password); 
} elsif ( $firstssh->error != 0 && $nodealhits < 3) {
	print "sendproc.pl: Warning: Oops, missed a leftover tarball ssh connection!Will try again in $postponetime microseconds!";
	$nodealhits=$nodealhits+1;
	print "sendproc.pl: Info: nodealhits is: $nodealhits \n";
	usleep($postponetime);
	sendfiles($server,$username,$password);
} else {
	system "./stopclient.pl";
	die "sendproc.pl Error: Unable to initiate an initial server SSH connection. CLIENT SHUTDOWN initiated. Bye! \n";
}


sub detectandsendleftovers {
	opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!";
	@crashleftovertarballs = sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}#[\w]*.tar.gz/  } readdir(DIR);
	closedir(DIR);

	if ( @crashleftovertarballs == 0) {
        	#The array is empty do nothing
        	print "The array is empty! \n";
	} else {
        	my $ssh = Net::OpenSSH->new($server, user => $username, password => $password, master_opts => [-o => "StrictHostKeyChecking=no"] );
        	if ( $ssh->error == 0 ) {
                	print "sendproc.pl: detectandsendleftovers subroutine: Success in SSH connection for leftover tarballs. Sending them. \n";
                	foreach my $leftovertarball (@crashleftovertarballs) {
                        	#Send and cleanup
                        	$ssh->scp_put({quiet=>0}, "/dev/shm/$leftovertarball", "/home/$username/");
                        	unlink ("/dev/shm/$leftovertarball");
                        } #end of foreach
        	} else {
                	print "sendproc.pl: detectandsendleftovers subroutine: Warning: Oops, missed a leftover tarball ssh connection!Will try again in $postponetime microseconds!";
                	usleep($postponetime);
                	foreach my $leftovertarball (@crashleftovertarballs) {
                        	#Send and cleanup
                        	$ssh->scp_put({quiet=>0}, "/dev/shm/$leftovertarball", "/home/$username/");
                       		 if ( $ssh->error == 0 ) {
                                	unlink ("/dev/shm/$leftovertarball");
                        	 } else {
                                	system "./stopclient.pl";
                                	die "sendproc.pl Error: detectandsendleftovers: Unable to initiate a leftover tarball connection. CLIENT SHUTDOWN initiated. Bye! \n";
                        	 }
                	} #end of foreach

        	} # end of $ssh->error == 0 else

	} #end of if (crashleftovertarballs == 0) ...


} #End of detectandsendleftovers subroutine

sub sendfiles {
	my $server=shift;
	my $username=shift;
	my $password=shift;

	#Set the global nodealhits counter to zero here.
	$nodealhits=0;

	while (1==1) {
		
		#First attempt to send a list of any leftovers
		detectandsendleftovers();
		#Then compress the freshly produced proc and netfiles
		#compressfiles(); 
		#Wait a bit for the files to compress
		#usleep($completiondelay);
		#Get a list of the POFR scanned proc and net compressed entries
		opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!"; 
		@sampledprocfiles = sort grep { /^[1-9][0-9]*\-\+[\d]{4}.proc/  } readdir(DIR);
		closedir(DIR);
		opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!";
		@samplednetfiles = sort grep { /^[1-9][0-9]*\-\+[\d]{4}.net/ } readdir(DIR);
		closedir(DIR);
		#What about leftovers from being unable to contact the server within an iteration of this infinite loop.
		opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!";
		@previterationtarballs=sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}#[\w]*.tar.gz/  } readdir(DIR);
		closedir(DIR);

	        print "Debug: sampled procfiles initially is @sampledprocfiles \n";

		#Send any leftover tarballs from the previous iteration of the while loop
		if ( @previterationtarballs == 0) {
        		#The array is empty do nothing 
        		print "The previterationtarballs array is empty! \n";
                } else {
			my $ssh = Net::OpenSSH->new($server, user => $username, password => $password, master_opts => [-o => "StrictHostKeyChecking=no"] );
			if ( $ssh->error == 0 ) {
                		$nodealhits=0;
                		print "sendproc.pl: main while loop: Success in SSH connection for leftover tarballs inside the while loop. Sending them. \n";
				foreach my $leftoverwhileloop (@crashleftovertarballs) {
                        		#Send and cleanup
                        		$ssh->scp_put({quiet=>0}, "/dev/shm/$leftoverwhileloop", "/home/$username/");
                        		unlink ("/dev/shm/$leftoverwhileloop");
                        	} #end of foreach
				undef @previterationtarballs;
			} else {
                		print "sendproc.pl: main while loop: Warning: Oops, missed an inner while loop leftover tarball ssh connection!Will try again in $postponetime microseconds!";
                		usleep($postponetime);
				foreach my $leftoverwhileloop (@crashleftovertarballs) {
                                        #Send and cleanup
                                        $ssh->scp_put({quiet=>0}, "/dev/shm/$leftoverwhileloop", "/home/$username/");
                                        if ($ssh->error == 0) {
						unlink ("/dev/shm/$leftoverwhileloop");
                                        } else {
						system "./stopclient.pl";
						print "sendproc.pl Error: Unable to initiate an inner while loop leftover tarball upload server SSH connection. Will defer to the next loop cycle of calling detectandsendleftovers(). \n";
					}
				} #end of foreach
			} #end of if ( $ssh->error == 0 ) else
		} #end of if ( @previterationtarballs == 0) { else ...
				
		
		#Small delay to ensure that all entries have completed writing once they have been scanned
		usleep($completiondelay);
	
		#Then select a slice of the sampled files to marshall the sending 
		#starting from the earliest recorded files
		@ftpscp=@sampledprocfiles[0..$procfilestosendatonce-1];
		@ftpscpnet=@samplednetfiles[0..$netfilestosendatonce-1];
		#Debug 
		print "proc slice @ftpscp \n";
		print "net slice @ftpscpnet \n";


		#Create the tarballs with the compressed files
		my ($secs, $microsecs)=gettimeofday;
		my $tz=strftime("%z", localtime());
		my $pmicrosecs=sprintf( "%06d", $microsecs );
		#open my $tarfh, ">", "/dev/shm/$secs$pmicrosecs-$tz.tar";
		#close $tarfh;
		my $tarball = Archive::Tar->new;
		$tarball->create_archive("/dev/shm/$secs$pmicrosecs#$tz.tar",0,"/dev/shm/lastreb.proc");

		foreach my $procfile (@ftpscp) {
			$tarball->add_files("/dev/shm/$procfile");
			unlink "/dev/shm/$procfile";
		}
		
		foreach my $netfile (@ftpscpnet) {
			$tarball->add_files("/dev/shm/$netfile");
			unlink "/dev/shm/$netfile";
		}

		#Now write the file the tar to /dev/shm, so far it is in memory.
		$tarball->write("/dev/shm/$secs$pmicrosecs#$tz.tar");

		#Compress the tarball 
		system "gzip /dev/shm/$secs$pmicrosecs#$tz.tar";

		#Ensure that we include the SHA256 hash as part of the compressed tarball
		#to detect file corruption from network outages or other reasons.
		my $shahash = Digest::SHA->new(256);
		$shahash->addfile("/dev/shm/$secs$pmicrosecs#$tz.tar.gz");
		my $digest = $shahash->hexdigest;
		#Debug 
		print "Digest of the compressed tar file is: $digest \n";

		rename "/dev/shm/$secs$pmicrosecs#$tz.tar.gz","/dev/shm/$secs$pmicrosecs#$tz#$digest.tar.gz";

		#And now send the renamed tarball over the network 
		my $ssh = Net::OpenSSH->new($server, user => $username, password => $password, master_opts => [-o => "StrictHostKeyChecking=no"] );
		if ( $ssh->error == 0 && $nodealhits < 3) {
			$nodealhits=0;
			$ssh->scp_put({quiet=>0}, "/dev/shm/$secs$pmicrosecs#$tz#$digest.tar.gz", "/home/$username/");
			#Delete the produced tar file
                	unlink ("/dev/shm/$secs$pmicrosecs#$tz#$digest.tar.gz");
			#Once you finish remove the contents of the scanned and file sending arrays
			undef @sampledprocfiles;
			undef @samplednetfiles;
			#undef @previterationtarballs;
			undef @ftpscp;
			undef @ftpscpnet;
			#Inner data build wait
			usleep($samplingloopdatabuildwait);
			
		} elsif ( $ssh->error != 0 && $nodealhits < 3 ) {
			print "sendproc.pl Warning: Oops, missed a connection while trying to upload a normal tarball file !Will try again in $postponetime microsecs! \n";
        		$nodealhits=$nodealhits+1;
        		print "sendproc.pl Info: nodealhits is: $nodealhits \n";
        		usleep($postponetime);
			$ssh->scp_put({quiet=>0}, "/dev/shm/$secs$pmicrosecs#$tz#$digest.tar.gz", "/home/$username/");
			if ($ssh->error == 0 ) {
				#Recovered connection
				$nodealhits=0;
				print "sendproc Info: Recocered after a while loop missed connection. \n";
				#Delete the produced tar file
				unlink ("/dev/shm/$secs$pmicrosecs#$tz#$digest.tar.gz");
				#Once you finish remove the contents of the scanned and file sending arrays
				undef @sampledprocfiles;
                        	undef @samplednetfiles;
				#undef @previterationtarballs;
                        	undef @ftpscp;
                        	undef @ftpscpnet;
                        	#Inner data build wait
                        	usleep($samplingloopdatabuildwait);
                        } else {
				#Nope we did not recover. Do not unlink the file,
				#bur clear the samepleproc-net and all the relevant arrays
				#and continue to the next iteration of the infinite while loop. 
				print "sendproc.pl Info: Did not recover after a while loop connection missapp. Did not manage to upload file /dev/shm/$secs$pmicrosecs#$tz#$digest.tar.gz \n";
				undef @sampledprocfiles;
                                undef @samplednetfiles;
				#undef @previterationtarballs;
                                undef @ftpscp;
                                undef @ftpscpnet;
                                #Inner data build wait
                                usleep($samplingloopdatabuildwait);
                                
			}
			
		} else {
			system "./stopclient.pl";
			die "Sendproc.pl Error: Uanble to connect to the server $server while sending normal tarball files. CLIENT SHUTDOWN initiated! \n";
		}

	} #end of infinite while loop

} #end of subroutine sendfiles
