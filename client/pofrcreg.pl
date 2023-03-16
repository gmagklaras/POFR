#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.36.0/x86_64-linux -I ../pofrperl/lib/5.36.0
#
use lib '../pofrperl/lib/site_perl/5.36.0';

#pofrcreg.pl - A script that registers a POFR client to a server.

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

#use Net::SSH::Perl;
use Net::SCP qw(scp iscp);
use Getopt::Long;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME
 ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use Sys::Hostname;
use Socket;

my $sdelay=10000000; #10 secs

#Essential sanity checks
my @whoami=getpwuid($<);
die "pofrcreg Error:You should execute this program ONLY with root privileges. You are not root.\n"
if ($whoami[2]!=0); 

sub dispusage {
	print "Usage: 	pofrcreg.pl --server SERVER_DNS_NAME_OR_IP_ADDRESS [--help] \n";
	print "Example:	pofrcreg.pl  --server myserver.mydomain.com \n";
	print "Note: This will prompt you to enter the registration password for that server. \n";
	print "      So, to use this tool, you will need to know the server DNS or IP AND the \n";
	print "      registration password. \n";
	exit;
}

my $server;
my $pass;
my $helpflag;
my $username="pofrsreg";

GetOptions("server=s" => \$server,
	   "help" => \$helpflag );

if ($helpflag) {
	dispusage;
}

if (! (defined($server))) {
        print "pofrcreg Error: You did not specify a server with the --server switch. I shall exit and do nothing! \n";
        dispusage;
}

#Get the hostname of the client
my $clienthostname=hostname;
my $clientipaddress = inet_ntoa((gethostbyname(hostname))[4]);

if (! (defined($clienthostname)) || ! (defined($clientipaddress)) ) {
	die "pofrcreg Error: Could not obtain essential IP and hostname data. Exiting. You might like to check the IP and hostname of the client. \n";
}

print "Hostname is  :  $clienthostname \n";
print "Client IP is :  $clientipaddress \n";

#Get the system UUID
my $uuidstr=`dmidecode --type system | grep UUID | cut -d":" -f2`;
$uuidstr=~ s/(^\s+|\s+$)//g;

#Get the timeref
open(TMR, "<","/proc/uptime");
my @timerefa=<TMR>;
close(TMR);
my @timerefstr=split " ", $timerefa[0];
my $timeref=$timerefstr[0];
$timeref=~ tr/'.'//d;

my $cidstr=$uuidstr . $timeref;

print "$cidstr \n";

#Generate the necessary RSA keys with passphrase the client ID string
#Keys should be of RSA type, be at least 4096 long have a passphrase and
#be local to the directory. No interference with localy generated root keys
#under /root/.ssh/. This keys are exclusively only for the POFR client-server
#session.
system "ssh-keygen -q -t rsa -b 4096 -N $cidstr -f ./pofr_rsa";

#Check that we have proper RSA key generation
die "pofrcreg.pl Error:Could not generate RSA keys: $!\n" if (! (-e "./pofr_rsa.pub")); 

#Read the Public RSA key
open(RSA, "<","./pofr_rsa.pub");
my $rsapub=<RSA>;
close(RSA);

#Create the request file with all the necessary data
open(RQF, ">", "./request$cidstr.pofr") or die "pofrcreg Error: Cannot create the request file: $! \n";
select RQF;
print "$clienthostname#$clientipaddress#$uuidstr#$cidstr#$rsapub";
close(RQF);

select STDOUT;

#Now send the request to the POFR server
#Connect to the POFR server
print "pofrcreg: OK. Connecting to the specified POFR server: $server to send our registration request. \n ";
my $scp=Net::SCP->new( {"host"=>$server, "user"=>$username} );
$scp->iscp("./request$cidstr.pofr", "$username\@$server:/home/$username/") or die $scp->{errstr};

print "pofrcreg: OK. Request sent successfully to server $server \n.";
#Wait a bit and keep attempting to obtain the response file from the server
do {{
	print "pofrcreg.pl: Waiting for the POFR server $server to respond on our request...\n";
	usleep($sdelay);
	$scp->iscp("$username\@$server:/home/$username/response$cidstr.reg", "./");
}} until (-e "./response$cidstr.reg");  

#Now open the retrieved response file and inform of the outcome. 

open(RESP, "<","./response$cidstr.reg");
my $resp=<RESP>;
close(RESP);
my @respdata=split "#",$resp;
my $result=shift @respdata;
my $message=shift @respdata;
my $email=shift @respdata;

if ($result eq "Status:GRANTED") {
	print "##########################################################################\n";
	print "#pofrcreg: STATUS: OK. Client $cidstr  #\n";
	print "#was registered at the POFR server: $server . # \n";
	print "##########################################################################\n";
	
	#In that case create the client authentication file
	open(AUTH, ">", "./.lcaf.dat") || die "pofrcreg Error: Cannot create the client authentication file: $! \n";
	select AUTH;
	#In the case of Status:Granted, $message is really the construid we need to SSH as and $email is the digest (password)
	print "Status:$server#$message#$email";
	close(AUTH);
	
  } else {
	  
	print "##########################################################################\n";
	print "#pofrcreg: STATUS: NOT OK. Client $cidstr  \n";
	print "#was denied registration, due to: $message #\n";
	print "#Please contact the POFR server administrator to resolve this.       #\n";
	print "##########################################################################\n";

}

#Eventually cleanup any left over request files
unlink glob "./*.pofr";



