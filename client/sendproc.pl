#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.36.0/x86_64-linux -I ../pofrperl/lib/5.36.0
#
use lib '../pofrperl/lib/site_perl/5.36.0';

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

my $completiondelay=300000;
my $initialdatabuildwait=128000000;
my $samplingloopdatabuildwait=45000000;
my $pspid="$$";

#Max number of files to send in each tarball 
my $procfilestosendatonce="384";
my $netfilestosendatonce="384";

#Node connection errors and transfer error counters 
my $nodechits=0;
my $nodethits=0;

#240 seconds (4 minutes) grace time when detecting bad connections
my $postponectime=240000000;

#120 seconds (2 minutes) grace time when detecting transfer errors
my $postponettime=120000000;

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
my $ssh = Net::OpenSSH->new($server, user => $username, password => $password, master_opts => [-o => "StrictHostKeyChecking=no"] );
if ($ssh->error == 0 && $nodechits < 3 ) {
        sendfiles($server,$username,$password,$ssh);
} elsif ( $ssh->error != 0 && $nodechits < 3) {
        print "sendproc.pl: Warning: Oops, missed a leftover tarball ssh connection!Will try again in $postponectime microseconds!";
        $nodechits=$nodechits+1;
        print "sendproc.pl: Info: nodechits is: $nodechits \n";
        usleep($postponectime);
        sendfiles($server,$username,$password,$ssh);
} else {
        system "./stopclient.pl";
        die "sendproc.pl Error: Unable to initiate an initial server SSH connection. CLIENT SHUTDOWN initiated. Bye! \n";
}

sub sendleftover {
        my $letovertarball=shift;
        my $ssh=shift; #Pass the Net::OpenSSH object by reference
        my $server=shift;
        my $username=shift;
        my $password=shift;

        #Is the detected tarball older than a couple of minutes?
        my ($currentsecs, $currentmicrosecs)=gettimeofday;
        my $tarfilesecs=substr($leftovertarball,0,10);
        my $timediff=$tarfilesecs-$currentsecs;
        if ($timediff <= 120) {
                #Send and cleanup if all is good
                $ssh->scp_put({quiet=>0}, "/dev/shm/$leftovertarball", "/home/$username/");
                if ($ssh->error == 0) {
                        print "sendproc.pl: sendleftover subroutine: Sent leftover file $leftovertarball which was less than 120 secs old. \n";
                        unlink ("/dev/shm/$leftovertarball");
                } else {
                        print "sendproc.pl sendleftover subroutine: Error with sending the leftovers, waiting for 10 seconds before trying again \n";
                        usleep(10000000);
                        $ssh->scp_put({quiet=>0}, "/dev/shm/$leftovertarball", "/home/$username/");
                        if ($ssh->error != 0) {
                                system "./stopclient.pl";
                                die "sendproc.pl Error: sendleftover: Unable to send leftover tarball $leftovertarball due to transfer error. CLIENT SHUTDOWN initiated. Bye! \n";
                        } else {
                                #We are back in business
                                print "sendproc.pl: sendleftover subroutine: Try 2: Sent the leftover file $leftovertarball with a 10 second delay. \n";
                                unlink ("/dev/shm/$leftovertarball");
                        } #end of if ($ssh->error != 0)

                } #end of if ($ssh->error == 0) ...

         } else {
                #File to send but is too old
                 print "sendproc.pl: sendleftover subroutine: File $leftovertarball is older than 120 seconds, so it will be discarded. \n";
                 unlink ("/dev/shm/$leftovertarball");
         } #end of if ($timediff <= 120) ...


} #end of sendleftover subroutine


sub detectandsendleftovers {
        #Detects whether there are any leftover tarballs. If there are, it will send them only if 
        #they are not more than a couple of minutes old. Data should not be left to stay more than a couple of minutes. 
        #for validity (possibility of alteration or out of sequence data detection).

        my $ssh=shift;

        opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!";
        @crashleftovertarballs = sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}#[\w]*.tar/  } readdir(DIR);
        closedir(DIR);

        if ( @crashleftovertarballs == 0) {
                #The array is empty do nothing
                print "sendproc Info: detectandsendleftovers subroutine: No leftover tarballs detected, good \n";
        } else {
                #We have stuff to send
                print "sendproc.pl: detectandsendleftovers subroutine: Leftover tarballs are detected. \n";
                my $ssh = Net::OpenSSH->new($server, user => $username, password => $password, master_opts => [-o => "StrictHostKeyChecking=no"] );
                foreach my $leftovertarball (@crashleftovertarballs) {
                        sendleftover($leftovertarball,$ssh,$server,$username,$password);


                } #end of foreach my $leftovertarball (@crashleftovertarballs)

        } # end of if ( @crashleftovertarballs == 0) 

} #End of detectandsendleftovers subroutine

sub sendfiles {
        my $server=shift;
        my $username=shift;
        my $password=shift;
        my $ssh=shift;

        #Set the global nodeconnectionhits and nodetransferhits counters to zero here.
        $nodechits=0;
        $nodethits=0;

        while (1==1) {

                #First of all attempt to send a list of any leftovers
                detectandsendleftovers();

                #Done with the leftovers, then get a list of the POFR scanned proc and net entries
                opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!";
                @sampledprocfiles = sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}.proc.gz/  } readdir(DIR);
                closedir(DIR);
                opendir(DIR, "/dev/shm") || die "sendproc Error: can't opendir /dev/shm: $!";
                @samplednetfiles = sort grep { /^[1-9][0-9]*#(\-|\+)[\d]{4}.net.gz/ } readdir(DIR);
                closedir(DIR);

                #Small delay to ensure that all entries have completed writing once they have been scanned
                usleep($completiondelay);

                #Then select a slice of the sampled files to marshall the sending 
                #starting from the earliest recorded files
                @ftpscp=@sampledprocfiles[0..$procfilestosendatonce-1];
                @ftpscpnet=@samplednetfiles[0..$netfilestosendatonce-1];
                #Debug 
                print "proc slice @ftpscp \n";
                print "net slice @ftpscpnet \n";

                #Create the tarballs with the files
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

                #Ensure that we include the SHA256 hash as part of the filename
                #to detect file corruption from network outages or other reasons.
                my $shahash = Digest::SHA->new(256);
                $shahash->addfile("/dev/shm/$secs$pmicrosecs#$tz.tar");
                my $digest = $shahash->hexdigest;
                #Debug 
                print "Digest of the tar file is: $digest \n";

                rename "/dev/shm/$secs$pmicrosecs#$tz.tar","/dev/shm/$secs$pmicrosecs#$tz#$digest.tar";

                #And now send the renamed tarball over the network 
                my $ssh = Net::OpenSSH->new($server, user => $username, password => $password, master_opts => [-o => "StrictHostKeyChecking=no"] );
                if ( $ssh->error == 0 && $nodealhits < 3) {
                        $nodealhits=0;
                        $ssh->scp_put({quiet=>0}, "/dev/shm/$secs$pmicrosecs#$tz#$digest.tar", "/home/$username/");
                        #Delete the produced tar file
                        unlink ("/dev/shm/$secs$pmicrosecs#$tz#$digest.tar");
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
                        $ssh->scp_put({quiet=>0}, "/dev/shm/$secs$pmicrosecs#$tz#$digest.tar", "/home/$username/");
                        if ($ssh->error == 0 ) {
                                #Recovered connection
                                $nodealhits=0;
                                print "sendproc Info: Recocered after a while loop missed connection. \n";
                                #Delete the produced tar file
                                unlink ("/dev/shm/$secs$pmicrosecs#$tz#$digest.tar");
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
                                print "sendproc.pl Info: Did not recover after a while loop connection missapp. Did not manage to upload file /dev/shm/$secs$pmicrosecs#$tz#$digest.tar \n";
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
                                                                                                                                                                                                                                  
