#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.42.1/x86_64-linux -I ../pofrperl/lib/5.42.1 -I ../lib
###
use lib '../pofrperl/lib/site_perl/5.42.1';

#findrange.pl - A script that helps the POFR engine detect/mine data from a certain date range

#POFR - Penguin OS Forensic (or Flight) Recorder - 
#A program that collects stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System 
#and derivatives.
#Copyright (C) 2021,2022,2023,2024,2025,2026 Georgios Magklaras

#Meteorologisk Institutt/The Norwegian Meteorological Institute, hereby disclaims all copyright interest in the program
#`POFR' (A program that collects stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System and derivatives ) 
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
use POFR;
use DBI;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use IO::File;
use Getopt::Long;
use DateTime;
use DateTime::Format::Duration;



my $usertoprocess=shift;


my ($pday,$pmonth,$pyear,$phour,$pmin,$psec,$lday,$lmonth,$lyear,$lhour,$lmin,$lsec)=find_data_time_range("bef5f0350b4a3395896f14d2926abcf5");

my $answer=check_requested_data_time_range("bef5f0350b4a3395896f14d2926abcf5","02","02","2022","23","02","21","20","03","2022","02","55","44");
print "Checking the requested date range returns : $answer \n";

my ($procref,$fileref,$netref)=get_requested_data_from_time_range("bef5f0350b4a3395896f14d2926abcf5","03","02","2022","20","32","01","03","02","2022","20","51","30");

#Check date_is_later_than_or_equal
my $datecheck1=date_is_later_than("02","02","2022","23","02","21","02","02","2022","23","02","21");
print "datecheck1 is : $datecheck1 \n";

#Check date_is_later than or equal
my $datecheck2=date_is_earlier_than("02","02","2022","23","02","21","02","02","2022","23","02","22");
print "datecheck2 is: $datecheck2 \n";

print "Getting the requested procdata time range returns: @$procref \n";
print "$pday,$pmonth,$pyear,$phour,$pmin,$psec,$lday,$lmonth,$lyear,$lhour,$lmin,$lsec";

