#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.38.2/x86_64-linux -I ../pofrperl/lib/5.38.2
#
use lib '../pofrperl/lib/site_perl/5.38.2';

# getsshfailedattempts.pl: A POFR server script that summarizes brute force attacks  on port 22 with GeoIP information by parsing the OS journal. It can be used to check
# the accuracy of the collected POFR info at the relational layer. To generate an input file, issue something like:
# journalctl -r -b -t sshd > data1.txt 
# Then invoke the program: ./getsshfailedattempts.pl data1.txt

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
use warnings;
use Geo::IP2Location;

my $journal_file = shift @ARGV;

die "Usage: $0 <journal_filename>\n" unless defined $journal_file;

# Path to your IP2Location database file (IP2LOCATION-LITE-DB1.IPV6.BIN or IP2LOCATION-LITE-DB1.BIN)
my $ip2location_db = './IP2LOCATION-LITE-DB3.BIN';

# Initialize IP2Location object with the database file
my $ip2location = Geo::IP2Location ->open($ip2location_db);

open(my $fh, '<', $journal_file) or die "Could not open file '$journal_file' $!";

my %failed_attempts;
my %ip_usernames;
my %ip_dates;
my %unique_countries;

my $first_attempt_time;
my $last_attempt_time;

while (my $line = <$fh>) {
    if ($line =~ /^(\w{3}\s+\d{1,3}\s+\d{1,3}:\d{1,3}:\d{1,3}).*Failed password for (\w+|\S+ user \w+) from (\d+\.\d+\.\d+\.\d+|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})/) {
        my $timestamp = $1;
        my $username = $2;
        my $ip_address = $3;

        if (!defined($first_attempt_time) || $timestamp lt $first_attempt_time) {
            $first_attempt_time = $timestamp;
        }
        if (!defined($last_attempt_time) || $timestamp gt $last_attempt_time) {
            $last_attempt_time = $timestamp;
        }

        $failed_attempts{$ip_address}{$timestamp}++;
        $ip_dates{$ip_address}{$timestamp} = 1;
        $ip_usernames{$ip_address}{$username} = 1 if $username ne 'invalid user'; # Skip 'invalid user' entries

        # Get country information using Geo::IP2Location
        my $record = $ip2location->get_country_short($ip_address);
        $unique_countries{$record}{'attempts'}++;
    }
}

close($fh);

print "First Failed Attempt: $first_attempt_time\n";
print "Last Failed Attempt: $last_attempt_time\n\n";

my @sorted_ips = sort { scalar keys %{$ip_usernames{$b}} <=> scalar keys %{$ip_usernames{$a}} } keys %ip_usernames;

foreach my $ip (@sorted_ips) {
    my @timestamps = sort keys %{$ip_dates{$ip}};
    my $num_usernames_used = scalar keys %{$ip_usernames{$ip}};

    print "IP Address: $ip\n";
    print "Dates of Failed Attempts:\n";
    foreach my $timestamp (@timestamps) {
        print "- $timestamp\n";
    }
    print "Failed Usernames:\n";
    foreach my $username (keys %{$ip_usernames{$ip}}) {
        print "- $username\n";
    }
    print "Number of Usernames Used: $num_usernames_used\n";

    # Get country information using Geo::IP2Location
    my $record = $ip2location->get_country_short($ip);
    print "Country: $record\n";
    print "\n";
}

# Summary
my $unique_ips = scalar keys %failed_attempts;
my $total_passwords = 0;
my $unique_countries = scalar keys %unique_countries;

foreach my $ip (keys %failed_attempts) {
    $total_passwords += scalar keys %{$failed_attempts{$ip}};
}

print "Summary:\n";
print "The system got probed by $unique_ips IP addresses.\n";
print "Total number of passwords tried: $total_passwords\n";
print "Probed from the following $unique_countries countries (sorted by failed attempts):\n";

# Sort countries by failed attempts in descending order
foreach my $country (sort { $unique_countries{$b}{'attempts'} <=> $unique_countries{$a}{'attempts'} } keys %unique_countries) {
    my $attempts = $unique_countries{$country}{'attempts'};
    print "- $country: $attempts attempts\n";
}
