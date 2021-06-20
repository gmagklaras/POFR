#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.32.1/x86_64-linux -I ../pofrperl/lib/5.32.1
#
use lib '../pofrperl/lib/site_perl/5.32.1';

#stopclient.pl: A script to stop the POFR client processes

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

use IO::File;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use POSIX;

#my $startclientpid="$$";
my $sendprocpid;
my $scanprocpid;
my $snetpid;

#Sanity checks
#Are we root?
#
chomp (my $result=`ps auxwww | grep sendproc.pl | grep -v grep`);
chomp (my $procres=`ps auxwww | grep scanproc.pl | grep -v grep`);
chomp (my $netres=`ps auxwww | grep scannet.pl | grep -v grep`);

if ($result || $procres || $netres) {
	system "killall -9 scanproc.pl scannet.pl; sleep 3; killall -9 sendproc.pl; rm .netpid; rm .scanpid; rm .sendpid";
} else {
	print "stopclient.pl Info: No active POFR client processes to stop. Exiting. \n";
}


		
