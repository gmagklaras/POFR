# POFR.pm: A Perl module that contains subroutine definitions for handling a range of functions 
# such as time management, data subset extraction, authentication and database connection functionality  

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


package POFR;
use strict;
use warnings;
use Exporter;
use Digest::SHA qw(sha1 sha1_hex sha256_hex);
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

our @ISA= qw( Exporter );

#Control what we export by default
our @EXPORT = qw( getdbauth dbtimestamp timestamp table_exists find_data_time_range check_requested_data_time_range date_is_later_than date_is_earlier_than get_requested_data_from_time_range determinepreviousthread sanitize_filename pofrgeoloc processnetfile);


#Subroutine definitions here
sub getdbauth {
        unless(open DBAUTH, "<./.adb.dat") {
                die "getdbath Error:POFR.pm: Could not open the .adb.dat file due to: $!";
                }

        my @localarray;

        while (<DBAUTH>) {
                my $dbentry=$_;
                chomp($dbentry);
                push(@localarray, $dbentry);
        }

        return @localarray;

} #end of getdbauth()

#Subroutine dbtimestamp: Gets a timesource from the database
sub dbtimestamp {
        #get the db authentication info
        my @authinfo=getdbauth();
        my ($username,$dbname,$dbpass,$hostname);

        foreach my $dbentry (@authinfo) {
                ($username,$dbname,$dbpass,$hostname)=split("," , $dbentry);
        }

        my $timestampsource="DBI:MariaDB:$dbname:$hostname";
        my $timestampservh=DBI->connect ($timestampsource, $username, $dbpass, {RaiseError => 1, PrintError => 1});

        my $tsSQLh=$timestampservh->prepare("select DATE_FORMAT(NOW(), '%Y-%m-%d-%k-%i-%s')");
        $tsSQLh->execute();

        my @timearray=$tsSQLh->fetchrow_array();
        my ($year,$month,$day,$hour,$min,$sec)=split("-",$timearray[0]);
        $tsSQLh->finish();
        return ($year,$month,$day,$hour,$min,$sec);
} #end of dbtimestamp subroutine

#Subroutine timestamp: Gets a date and time from the POFR tarball to reflect the time zone of the client
sub timestamp {
        my $epoch=shift;
        my $time_zone=shift;

        #The epoch value we get is epoch plus msec. The msec value needs to come off.
        my $epochminusmsec=substr $epoch,0,10;

        my $dt=DateTime->from_epoch( epoch => $epochminusmsec );
        #Here we set the time zone acquired from the POFR client
        #to ensure that we report the time/hour on the server properly.
        $dt->set_time_zone( $time_zone );

        my $calcyear=$dt->year;
        my $calcmonth=$dt->month;
        my $day_of_month=$dt->day;
        my $calchour=$dt->hour;
        my $calcmin=$dt->minute;
        my $calcsec=$dt->second;

        return ($calcyear,$calcmonth,$day_of_month,$calchour,$calcmin,$calcsec);

} #end of timestamp


sub table_exists {
    my $db = shift;
    my $table = shift;
    my @tables = $db->tables('','','','TABLE');
    if (@tables) {
        for (@tables) {
            next unless $_;
            return 1 if $_ eq $table
        }
    }
    else {
        eval {
            local $db->{PrintError} = 0;
            local $db->{RaiseError} = 1;
            $db->do(qq{SELECT * FROM $table WHERE 1 = 0 });
        };
        return 1 unless $@;
    }
    return 0;
} #End of table_exists subroutine

#subroutine sanitize_filename - Removes certain characters (#) and checks the length of the filename
#so that it will not cause problems when SQL inserted to the database
#ACCEPTS: -the parsed filename string
#RETURNS: -the sanitized filename string
sub sanitize_filename {

        my $fnstring = shift;
        #Remove a '#' character from the string. That could
        #really break our data encoding techniques
        $fnstring =~ s/#//g;
	#Replace white space with triple underscore to avoid the bug of 
	#braking up the filename into multiple entries in the RDBMS.
	$fnstring =~ s/\s/___/g;
        #Also check if the string is greater than 4k characters which is the limit
        #of the maximum file path in the database.
	return substr($fnstring, 0, 4095);

} #End of sanitize_filename

sub iso8601_date {
  die unless $_[0] =~ m/^(\d\d\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)Z$/;
  return DateTime->new(year => $1, month => $2, day => $3,
    hour => $4, minute => $5, second => $6, time_zone  => 'UTC');
}

# sub find_data_time_range: Find the date range of stored data into POFR for a user
# ACCEPTS: A username
# RETURNS: A list of pdata (initial data) and ldata (last data)
sub find_data_time_range {
	my $usertoprocess=shift;
	my @authinfo=getdbauth();
	my ($dbusername,$dbname,$dbpass,$hostname);

	foreach my $dbentry (@authinfo) {
	($dbusername,$dbname,$dbpass,$hostname)=split("," , $dbentry);
	}

	my $fdtrsource="DBI:MariaDB:$dbname:$hostname";
	my $fdtrservh=DBI->connect ($fdtrsource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	my $fdtrSQLh=$fdtrservh->prepare("SELECT COUNT(*) FROM lhltable where ciduser='$usertoprocess'");
	$fdtrSQLh->execute();
	my @cidhits=$fdtrSQLh->fetchrow_array();
	if ($cidhits[0] >= "1") {
        	print "finddatarange subroutine Status: Detected user $usertoprocess in the database...\n";
	} else {
        	$fdtrSQLh->finish();
        	die "finddatarange subroutine Error: Could not detect user $usertoprocess in the database. Are you sure the lhltable is not out of sync? \n";
	}

	#Get the db name for that user
	$fdtrSQLh=$fdtrservh->prepare("SELECT cid FROM lhltable WHERE ciduser='$usertoprocess' ");
	$fdtrSQLh->execute();
	my @dbnamehits=$fdtrSQLh->fetchrow_array();
	$fdtrSQLh->finish();
	my $ldb=$dbnamehits[0];
	$ldb =~ s/-//g;

	$fdtrsource="DBI:MariaDB:$ldb:$hostname";
	my $hostservh=DBI->connect ($fdtrsource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	$hostservh->do('SET NAMES utf8mb4');

	$fdtrSQLh=$hostservh->prepare("show tables LIKE 'archpsinfo%'");
	$fdtrSQLh->execute();

	my @rangehits;
	while ( my $row=$fdtrSQLh->fetchrow()) {
		push (@rangehits,$row);
	}

	#Now we have to get the dates and times of the first and last piece of data
        #Select the first row of the first archpsinfo table
        my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec);
        my ($lyear,$lmonth,$lday,$lhour,$lmin,$lsec,$lmsec);

        
        $fdtrSQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $rangehits[0] LIMIT 1" );
        $fdtrSQLh->execute();
        my @pdata=$fdtrSQLh->fetchrow_array();

        #Listifying the @pdata array
        ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@pdata[0..$#pdata];

        #Then select the last record of the LAST archpsinfo table
        $fdtrSQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $rangehits[-1] ORDER BY psentity DESC LIMIT 1" );
        $fdtrSQLh->execute();
        my @ldata=$fdtrSQLh->fetchrow_array();

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

	$hostservh->disconnect;

	return ($pday,$pmonth,$pyear,$phour,$pmin,$psec,$lday,$lmonth,$lyear,$lhour,$lmin,$lsec);


	#print "From: $pday/$pmonth/$pyear - $phour:$pmin:$psec TO $lday/$lmonth/$lyear - $lhour:$lmin:$lsec \n";

	#my $dp=iso8601_date("$pyear-$pmonth-$pday"."T"."$phour:$pmin:$psec"."Z");
	#my $dl=iso8601_date("$lyear-$lmonth-$lday"."T"."$lhour:$lmin:$lsec"."Z");

	#my $datedelta= $dl->delta_days($dp)->delta_days();
	##my $hourdelta= $dl->delta_hours($dp)->delta_hours();


	#print "$datedelta days  worth of data \n"; 
} #End of find_data_time subroutine

# sub check_requested_data_time_range: Finds if a requested time range for the data is feasible
# ACCEPTS: a user name and a list of requested data (rdata) 
# RETURNS: "True", if the requested data exists/is in range
# 	   "False", if the requested data does not exist/is NOT in range
# 	   "Error", if the requested data are malformed and the query cannot be executed
sub check_requested_data_time_range {
	#Returns True if the requested data are in range
	#Returns False if the requested data are not in range
	#Returns ERR if the requested data are out of time scope
	my $usertoprocess=shift;
	my $rpday=shift;
	my $rpmonth=shift;
	my $rpyear=shift;
	my $rphour=shift;
	my $rpmin=shift;
	my $rpsec=shift;
	my $rlday=shift;
        my $rlmonth=shift;
        my $rlyear=shift;
        my $rlhour=shift;
        my $rlmin=shift;
        my $rlsec=shift;
	
	#Check for invalid requested data
	if ( $rpday>=32 || $rlday>=32 ) { return "ERR";}
	if ( $rpmonth>=13 || $rlmonth>=13 ) { return "ERR";}
	if ( $rphour>=24 || $rlhour>=24) { return "ERR";}
	if ( $rpmin>=60 || $rlmin>=60 ) { return "ERR";}
	if ( $rpsec>=60 || $rlsec>=60 ) { return "ERR";}

	#Is the final requested range before the initial requested range (input error)?
	my $prdata = DateTime->new(
		year      => $rpyear,
                month     => $rpmonth,
                day       => $rpday,
                hour      => $rphour,
                minute    => $rpmin,
                second    => $rpsec,
        );

	my $lrdata = DateTime->new( 
		year      => $rlyear,
                month     => $rlmonth,
                day       => $rlday,
                hour      => $rlhour,
                minute    => $rlmin,
                second    => $rlsec,
        );

	my $inputdelta = $lrdata->subtract_datetime($prdata);

	my $istatus = DateTime::Format::Duration->new(pattern => '%Y,%m,%e,%H,%M,%S');

        my @ind= split(',', $istatus->format_duration($inputdelta));
        my $negind=0;
        foreach (@ind) {
                if (!($_ >=0)) { $negind=$negind+1; };
        }
	
	if (!($negind=="0")) {
		return "ERR";
	}

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
                print "check_requested_data_time_range subroutine Status: Detected user $usertoprocess in the database...\n";
        } else {
                $SQLh->finish();
                die "check_requested_data_time_range Error: Could not detect user $usertoprocess in the database. Are you sure the lhltable is not out of sync? \n";
        }

        my ($dpday,$dpmonth,$dpyear,$dphour,$dpmin,$dpsec,$dlday,$dlmonth,$dlyear,$dlhour,$dlmin,$dlsec)=find_data_time_range("$usertoprocess");

	#Are the requested rpdata more or equally recent than the stored dpdata?
	my $dpdata = DateTime->new(
		year      => $dpyear,
    		month     => $dpmonth,
    		day       => $dpday,
    		hour      => $dphour,
    		minute    => $dpmin,
		second	  => $dpsec,
	);

	my $rpdata = DateTime->new(
        	year      => $rpyear,
        	month     => $rpmonth,
        	day       => $rpday,
        	hour      => $rphour,
        	minute    => $rpmin,
		second    => $rpsec,
	); 

	my $pdelta = $rpdata->subtract_datetime($dpdata);

	my $pstatus = DateTime::Format::Duration->new(pattern => '%Y,%m,%e,%H,%M,%S');

	my @cpd= split(',', $pstatus->format_duration($pdelta));
	my $negcpd=0;
	foreach (@cpd) {
		if (!($_ >=0)) { $negcpd=$negcpd+1; };
	}
	

	#Are the requested rldata less or equally recent than the stored dldata?
	my $dldata = DateTime->new(
                year      => $dlyear,
                month     => $dlmonth,
                day       => $dlday,
                hour      => $dlhour,
                minute    => $dlmin,
                second    => $dlsec,
        );

	my $rldata = DateTime->new(
                year      => $rlyear,
                month     => $rlmonth,
                day       => $rlday,
                hour      => $rlhour,
                minute    => $rlmin,
                second    => $rlsec,
        );

	my $ldelta = $dldata->subtract_datetime($rldata);

	my $lstatus = DateTime::Format::Duration->new(pattern => '%Y,%m,%e,%H,%M,%S');
	
	my @cld=split(',', $lstatus->format_duration($ldelta));
	my $negcld=0;
        foreach (@cld) {
                if (!($_ >=0)) { $negcld=$negcld+1; };
        }

	#Finally conclude if we do not have negative delta on either of the two checks we are OK
	#otherwise we are NOT 
	if ( $negcpd=="0" && $negcld=="0") {
		return "True";
	} else {
		return "False";
	}


} #End of check_requested_data_time_range subroutine

#sub date_is_later_than: Examines whether specified date and time B is later than date and time A. 
#ACCEPTS: Two distinct dates and times A and B
#RETURNS: "True" if B is later than A
#         "False" if B is earlier than or equal to A
sub date_is_later_than {
	my $Aday=shift;
        my $Amonth=shift;
        my $Ayear=shift;
        my $Ahour=shift;
        my $Amin=shift;
        my $Asec=shift;
        my $Bday=shift;
        my $Bmonth=shift;
        my $Byear=shift;
        my $Bhour=shift;
        my $Bmin=shift;
        my $Bsec=shift;

	my $dateA = DateTime->new(
        	year      => $Ayear,
        	month     => $Amonth,
        	day       => $Aday,
                hour      => $Ahour,
                minute    => $Amin,
                second    => $Asec,
        );

	my $dateB = DateTime->new(
                year      => $Byear,
                month     => $Bmonth,
                day       => $Bday,
                hour      => $Bhour,
                minute    => $Bmin,
                second    => $Bsec,
        );

	my $delta = DateTime->compare($dateB, $dateA);

	if ( $delta > "0") {
	       return "True";
	} else {
 	       return "False";
	}	       


} #End of subroutine date_is_later_than 

#sub date_is_earlier_than: Examines whether specified date and time B is earlier than date and time A.
#ACCEPTS: Two distinct dates and times A and B
#RETURNS: "True" if B is earlier than A
#         "False" if B is later than or equal (coincides) to A
sub date_is_earlier_than {
        my $Aday=shift;
        my $Amonth=shift;
        my $Ayear=shift;
        my $Ahour=shift;
        my $Amin=shift;
        my $Asec=shift;
        my $Bday=shift;
        my $Bmonth=shift;
        my $Byear=shift;
        my $Bhour=shift;
        my $Bmin=shift;
        my $Bsec=shift;

        my $dateA = DateTime->new(
                year      => $Ayear,
                month     => $Amonth,
                day       => $Aday,
                hour      => $Ahour,
                minute    => $Amin,
                second    => $Asec,
        );

        my $dateB = DateTime->new(
                year      => $Byear,
                month     => $Bmonth,
                day       => $Bday,
                hour      => $Bhour,
                minute    => $Bmin,
                second    => $Bsec,
        );

	my $delta = DateTime->compare($dateB, $dateA);
	
	if ( $delta < "0") {
               return "True";
        } else {
               return "False";
        }


} #End of subroutine date_is_earlier_than


#sub get_requested_data_from_time_range: Provides a list of archtables from a requested/specified data time range
#ACCEPTS: a username and a specified/requested time range
#RETURNS: -Three array references: \@targetprocarchtables, \@targetfilearchtables and \@targetnetarchtables, 
#	   each containing the arch relational tables for the requested time range, *if* the data exists
#	  -Three array references: \@targetprocarchtables, \@targetfilearchtables and \@targetnetarchtables,
#	   each containing a single "NODATA" OR "ERROR" element, depending on whether the data does not exist 
#	   or if there is another problem with the query.
sub get_requested_data_from_time_range {
	my $usertoprocess=shift;
	my $rpday=shift;
        my $rpmonth=shift;
        my $rpyear=shift;
        my $rphour=shift;
        my $rpmin=shift;
        my $rpsec=shift;
        my $rlday=shift;
        my $rlmonth=shift;
        my $rlyear=shift;
        my $rlhour=shift;
        my $rlmin=shift;
        my $rlsec=shift;

	#ubcheck -> Upper Bound Date check
	#target -> final results of Lower Bound Date check (see further down in the subroutine)
	my @ubcheckprocarchtables;
	my @ubcheckfilearchtables;
	my @ubchecknetarchtables;
	my @targetprocarchtables;
	my @targetfilearchtables;
	my @targetnetarchtables;

	
	#Are the requested data in time range with what is stored in the RDBMS
	my $answer=check_requested_data_time_range($usertoprocess,$rpday,$rpmonth,$rpyear,$rphour,$rpmin,$rpsec,$rlday,$rlmonth,$rlyear,$rlhour,$rlmin,$rlsec);
        if ( $answer eq "True" ) {
		#Connect to the database
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
                	print "finddatarange subroutine Status: Detected user $usertoprocess in the database...\n";
        	} else {
                	$SQLh->finish();
                	die "finddatarange subroutine Error: Could not detect user $usertoprocess in the database. Are you sure the lhltable is not out of sync? \n";
        	}

       		#Get the db name for that user
        	$SQLh=$lhltservh->prepare("SELECT cid FROM lhltable WHERE ciduser='$usertoprocess' ");
        	$SQLh->execute();
       		my @dbnamehits=$SQLh->fetchrow_array();
        	$SQLh->finish();
        	my $ldb=$dbnamehits[0];
        	$ldb =~ s/-//g;

        	$datasource="DBI:MariaDB:$ldb:$hostname";
        	my $hostservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
       		$hostservh->do('SET NAMES utf8mb4');

		#Sense what do we have in the data store
		my @myparchtables=$hostservh->tables('', $ldb, 'archpsinfo%', 'TABLE');
		my @myfarchtables=$hostservh->tables('', $ldb, 'archfileinfo%', 'TABLE');
        	my @mynarchtables=$hostservh->tables('', $ldb, 'archnetinfo%', 'TABLE');

		#Selection/filtering of the relevant proctables
		foreach my $currentptable (@myparchtables) {
			#Now we have to get the dates and times of the first and last piece of data
        		#Select the firstand last row of the current archpsinfo table 
			$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentptable LIMIT 1" );
        		$SQLh->execute();
        		my @pdata=$SQLh->fetchrow_array();

        		#Listifying the @pdata array
       			my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@pdata[0..$#pdata];

        		#Then select the last record of the current table
        		$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentptable ORDER BY psentity DESC LIMIT 1" );
        		$SQLh->execute();
        		my @ldata=$SQLh->fetchrow_array();

        		#Listifying the @ldata array
        		my ($lyear,$lmonth,$lday,$lhour,$lmin,$lsec,$lmsec)=@ldata[0..$#ldata];

			#First stage of the two stage algorithm check (Upper and Lower Bound Date check)
			#Checking the Upper Bound Date first:
			#Is the requested last date after the last date of the current table?
			#If yes, push the table into the ubcheckprocarchtables array
			my $ubcheck=date_is_later_than($lday,$lmonth,$lyear,$lhour,$lmin,$lsec,$rlday,$rlmonth,$rlyear,$rlhour,$rlmin,$rlsec);
			if ( $ubcheck eq "True") {
				print "ubcheck: date_is_later than returned True, so we push $currentptable \n";
				push(@ubcheckprocarchtables, $currentptable);
			} elsif ( $ubcheck eq "False") {
				print "ubcheck: date_is_later than returned False, so we push $currentptable and exit the loop \n";
				push(@ubcheckprocarchtables, $currentptable);
				last;
			}	

		     

		} #End of foreach my $currentptable (@myparchtables)

		#Having the @ubcheckprocarchtables Upper Bound check array populated, we start the Lower Bound detection
		#by reversing that array to start working from its last element.
		my @revubcheckprocarchtables=reverse(@ubcheckprocarchtables); 
		my @lastptoreverse;
		foreach my $currentrevtable (@revubcheckprocarchtables) {
			$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentrevtable LIMIT 1" );
                        $SQLh->execute();
                        my @revpdata=$SQLh->fetchrow_array();

			#Listifying the @pdata array
                        my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@revpdata[0..$#revpdata];

			#Second stage of the two stage algorithm check (Upper and Lower Bound Date check)
			#Checking the Lower Bound Date now:
			#Is the requested primary date earlier that the primary date of this table?
			#If yes push the table into the @targetprocarchtables array
			my $lbcheck=date_is_earlier_than($pday,$pmonth,$pyear,$phour,$pmin,$psec,$rpday,$rpmonth,$rpyear,$rphour,$rpmin,$rpsec);
			if ( $lbcheck eq "True") {
				print "lbcheck: date_is_earlier_than returned True, so we push $currentrevtable \n";
				push (@lastptoreverse,shift(@revubcheckprocarchtables));
			} elsif ( $lbcheck eq "False") {
				push (@lastptoreverse,shift(@revubcheckprocarchtables));
				print "lbcheck: date_is_earlier_than returned False, so we push $currentrevtable and exit the loop \n";
				last;
			}
		
		}

		
		#Reverse to the final array that we are going to return
		@targetprocarchtables=reverse(@lastptoreverse);

		print "Debug: targetprocarchtables is  @targetprocarchtables \n";
		
		#Processing/filtering of the relevant file tables
		foreach my $currentftable (@myfarchtables) {
			#First record of the current table
			$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentftable LIMIT 1" );
                        $SQLh->execute();
                        my @fdata=$SQLh->fetchrow_array();

			#Listifying the @fdata array
                        my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@fdata[0..$#fdata];

			#Then select the last record of the current table
                        $SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentftable ORDER BY fileaccessid DESC LIMIT 1" );
                        $SQLh->execute();
                        my @ldata=$SQLh->fetchrow_array();

			#Listifying the @ldata array
                        my ($lyear,$lmonth,$lday,$lhour,$lmin,$lsec,$lmsec)=@ldata[0..$#ldata];

			#First stage of the two stage algorithm check (Upper and Lower Bound Date check)
                        #Checking the Upper Bound Date first:
                        #Is the requested last date after the last date of the current table?
                        #If yes, push the table into the ubcheckprocarchtables array
                        my $ubcheck=date_is_later_than($lday,$lmonth,$lyear,$lhour,$lmin,$lsec,$rlday,$rlmonth,$rlyear,$rlhour,$rlmin,$rlsec);
			if ( $ubcheck eq "True") {
                                print "ubcheck: date_is_later than returned True, so we push $currentftable \n";
                                push(@ubcheckfilearchtables, $currentftable);
                        } elsif ( $ubcheck eq "False") {
                                print "ubcheck: date_is_later than returned False, so we push $currentftable  and exit the loop \n";
                                push(@ubcheckfilearchtables, $currentftable);
                                last;
                        }


		} #End of foreach my $currentftable (@myfarchtables)

		#Having the @ubcheckfilearchtables Upper Bound check array populated, we start the Lower Bound detection
                #by reversing that array to start working from its last element.
		my @revubcheckfilearchtables=reverse(@ubcheckfilearchtables);
                my @lastftoreverse;

		foreach my $currentfrevtable (@revubcheckfilearchtables) {
                        $SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentfrevtable LIMIT 1" );
                        $SQLh->execute();
                        my @revfdata=$SQLh->fetchrow_array();

                        #Listifying the @revfdata array
                        my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@revfdata[0..$#revfdata];

                        #Second stage of the two stage algorithm check (Upper and Lower Bound Date check)
                        #Checking the Lower Bound Date now:
                        #Is the requested primary date earlier that the primary date of this table?
                        #If yes push the table into the @targetprocarchtables array
                        my $lbcheck=date_is_earlier_than($pday,$pmonth,$pyear,$phour,$pmin,$psec,$rpday,$rpmonth,$rpyear,$rphour,$rpmin,$rpsec);
                        if ( $lbcheck eq "True") {
                                print "lbcheck: date_is_earlier_than returned True, so we push $currentfrevtable \n";
                                push (@lastftoreverse,shift(@revubcheckfilearchtables));
                        } elsif ( $lbcheck eq "False") {
                                push (@lastftoreverse,shift(@revubcheckfilearchtables));
                                print "lbcheck: date_is_earlier_than returned False, so we push $currentfrevtable and exit the loop \n";
                                last;
                        }

                }

		#Reverse to the final array that we are going to return
                @targetfilearchtables=reverse(@lastftoreverse);

                print "Debug: targetfilearchtables is  @targetfilearchtables \n";

		#Processing/filtering of the relevant network tables
		foreach my $currentntable (@mynarchtables) {
			#First record of the current table
                        $SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentntable LIMIT 1" );
                        $SQLh->execute();
                        my @ndata=$SQLh->fetchrow_array();

			#Listifying the @ndata array
                        my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@ndata[0..$#ndata];

			#Then select the last record of the current table
                        $SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentntable ORDER BY endpointinfo DESC LIMIT 1" );
                        $SQLh->execute();
                        my @ldata=$SQLh->fetchrow_array();

			#Listifying the @ldata array
                        my ($lyear,$lmonth,$lday,$lhour,$lmin,$lsec,$lmsec)=@ldata[0..$#ldata];
			
			#First stage of the two stage algorithm check (Upper and Lower Bound Date check)
                        #Checking the Upper Bound Date first:
                        #Is the requested last date after the last date of the current table?
                        #If yes, push the table into the ubcheckprocarchtables array
                        my $ubcheck=date_is_later_than($lday,$lmonth,$lyear,$lhour,$lmin,$lsec,$rlday,$rlmonth,$rlyear,$rlhour,$rlmin,$rlsec);
			if ( $ubcheck eq "True") {
                                print "ubcheck: date_is_later than returned True, so we push $currentntable \n";
                                push(@ubchecknetarchtables, $currentntable);
                        } elsif ( $ubcheck eq "False") {
                                print "ubcheck: date_is_later than returned False, so we push $currentntable  and exit the loop \n";
                                push(@ubchecknetarchtables, $currentntable);
                                last;
                        }

		} #End of foreach my $currentntable (@mynarchtables)

		#Having the @ubchecknetarchtables Upper Bound check array populated, we start the Lower Bound detection
                #by reversing that array to start working from its last element.
                my @revubchecknetarchtables=reverse(@ubchecknetarchtables);
                my @lastntoreverse;

		foreach my $currentnrevtable (@revubchecknetarchtables) {
			$SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $currentnrevtable LIMIT 1" );
                        $SQLh->execute();
                        my @revndata=$SQLh->fetchrow_array();

                        #Listifying the @revndata array
                        my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@revndata[0..$#revndata];
			
			#Second stage of the two stage algorithm check (Upper and Lower Bound Date check)
                        #Checking the Lower Bound Date now:
                        #Is the requested primary date earlier that the primary date of this table?
                        #If yes push the table into the @targetprocarchtables array
                        my $lbcheck=date_is_earlier_than($pday,$pmonth,$pyear,$phour,$pmin,$psec,$rpday,$rpmonth,$rpyear,$rphour,$rpmin,$rpsec);
			if ( $lbcheck eq "True") {
                                print "lbcheck: date_is_earlier_than returned True, so we push $currentnrevtable \n";
                                push (@lastntoreverse,shift(@revubchecknetarchtables));
                        } elsif ( $lbcheck eq "False") {
                                push (@lastntoreverse,shift(@revubchecknetarchtables));
                                print "lbcheck: date_is_earlier_than returned False, so we push $currentnrevtable and exit the loop \n";
                                last;
                        }

			
		} #End of foreach my $currentnrevtable (@revubchecknetarchtables)

		#Reverse to the final array that we are going to return
                @targetnetarchtables=reverse(@lastntoreverse);

                print "Debug: targetnetarchtables is  @targetnetarchtables \n";

		
		#Return a list containing the three array references
		return (\@targetprocarchtables, \@targetfilearchtables, \@targetnetarchtables);

	} elsif ( $answer eq "False") {
		#Here we have had no data in range, because check_requested_data_time_range()
		#claimed the request was out of range.
	        push (@targetprocarchtables, "NODATA");
		push (@targetfilearchtables, "NODATA");
		push (@targetnetarchtables, "NODATA");
		return (\@targetprocarchtables, \@targetfilearchtables, \@targetnetarchtables);

	} else {
		#Here we probably have a malformed query, because check_requested_data_time_range()
                #claimed something else was wrong.
		push (@targetprocarchtables, "ERROR");
                push (@targetfilearchtables, "ERROR");
                push (@targetnetarchtables, "ERROR");
                return (\@targetprocarchtables, \@targetfilearchtables, \@targetnetarchtables);

	}



} #End of subroutine get_requested_data_time_range


#sub determinepreviousthread: Determines the previous thread, to provide thread marshaling/synchronization
#ACCEPTS: -a POFR username, and 
#         -the current thread first time stamp (fts), 
#SETS   : -the previous thread first time stamp (fts), 
#         -the previous thread last time stamp (lts), 
#         -the thread number (indicating thread order, 1-32, 1 is the first thread), 
#         -the first thread first time stamp fts, 
#         -the first thread last time stamp lts  
sub determinepreviousthread {
        my $user=shift;
        my $currentfts=shift;
        my $previousfts;
        my $previouslts;
        my $threadnum;
        my $firstthreadfts;
        my $firstthreadlts;

        opendir(THORDER, "/home/$user/proc") || die "POFR.pm Error: Inside the determinepreviousthread subroutine: THREAD NUMBER $threadnum: Can't open user directory /home/$user/proc to perform thread ordering due to : $!";
        my @threadirs = sort grep { /^[1-9][0-9]*\-[1-9][0-9]/ } readdir(THORDER);
        my @timestampsarray;
        foreach my $tdir (@threadirs) {
                push @timestampsarray, split "-",$tdir;
        } #end of foreach my $tdir

	#Debug
	print "Determinepreviousthread subroutine: timestampsarray is: @timestampsarray \n";

        my @threadfts=($timestampsarray[0],$timestampsarray[2],$timestampsarray[4],$timestampsarray[6],$timestampsarray[8],$timestampsarray[10],$timestampsarray[12],$timestampsarray[14],$timestampsarray[16],$timestampsarray[18],$timestampsarray[20],$timestampsarray[22],$timestampsarray[24],$timestampsarray[26],$timestampsarray[28],$timestampsarray[30],$timestampsarray[32],$timestampsarray[34],$timestampsarray[36],$timestampsarray[38],$timestampsarray[40],$timestampsarray[42],$timestampsarray[44],$timestampsarray[46],$timestampsarray[48],$timestampsarray[50],$timestampsarray[52],$timestampsarray[54],$timestampsarray[56],$timestampsarray[58],$timestampsarray[60],$timestampsarray[62]);
        my @threadlts=($timestampsarray[1],$timestampsarray[3],$timestampsarray[5],$timestampsarray[7],$timestampsarray[9],$timestampsarray[11],$timestampsarray[13],$timestampsarray[15],$timestampsarray[17],$timestampsarray[19],$timestampsarray[21],$timestampsarray[23],$timestampsarray[25],$timestampsarray[27],$timestampsarray[29],$timestampsarray[31],$timestampsarray[33],$timestampsarray[35],$timestampsarray[37],$timestampsarray[39],$timestampsarray[41],$timestampsarray[43],$timestampsarray[45],$timestampsarray[47],$timestampsarray[49],$timestampsarray[51],$timestampsarray[53],$timestampsarray[55],$timestampsarray[57],$timestampsarray[59],$timestampsarray[61],$timestampsarray[63]);

        foreach my $fts (@threadfts) {
                if ($currentfts == $timestampsarray[0]) {
                        $previousfts="none";
                        $previouslts="none";
                        $threadnum=1;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1]; }
                elsif ($currentfts == $timestampsarray[2] ) {
                        $previousfts=$timestampsarray[0];
                        $previouslts=$timestampsarray[1];
                        $threadnum=2;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1]; }
                elsif ($currentfts == $timestampsarray[4] ) {
                        $previousfts=$timestampsarray[2];
                        $previouslts=$timestampsarray[3];
                        $threadnum=3;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1]; }
                elsif ($currentfts == $timestampsarray[6]) {
                        $previousfts=$timestampsarray[4];
                        $previouslts=$timestampsarray[5];
                        $threadnum=4;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1]; }
                elsif ($currentfts == $timestampsarray[8]) {
                        $previousfts=$timestampsarray[6];
                        $previouslts=$timestampsarray[7];
                        $threadnum=5;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1]; }
                elsif ($currentfts == $timestampsarray[10]) {
                        $previousfts=$timestampsarray[8];
                        $previouslts=$timestampsarray[9];
                        $threadnum=6;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1]; }
                elsif ($currentfts == $timestampsarray[12]) {
                        $previousfts=$timestampsarray[10];
                        $previouslts=$timestampsarray[11];
                        $threadnum=7;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1]; }
                elsif ($currentfts == $timestampsarray[14]) {
                        $previousfts=$timestampsarray[12];
                        $previouslts=$timestampsarray[13];
                        $threadnum=8;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1]; }
                elsif ($currentfts == $timestampsarray[16]) {
                        $previousfts=$timestampsarray[14];
                        $previouslts=$timestampsarray[15];
                        $threadnum=9;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[18]) {
                        $previousfts=$timestampsarray[16];
                        $previouslts=$timestampsarray[17];
                        $threadnum=10;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[20]) {
                        $previousfts=$timestampsarray[18];
                        $previouslts=$timestampsarray[19];
                        $threadnum=11;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[22]) {
                        $previousfts=$timestampsarray[20];
                        $previouslts=$timestampsarray[21];
                        $threadnum=12;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[24]) {
                        $previousfts=$timestampsarray[22];
                        $previouslts=$timestampsarray[23];
                        $threadnum=13;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[26]) {
                        $previousfts=$timestampsarray[24];
                        $previouslts=$timestampsarray[25];
                        $threadnum=14;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[28]) {
                        $previousfts=$timestampsarray[26];
                        $previouslts=$timestampsarray[27];
                        $threadnum=15;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[30]) {
                        $previousfts=$timestampsarray[28];
                        $previouslts=$timestampsarray[29];
                        $threadnum=16;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[32]) {
                        $previousfts=$timestampsarray[30];
                        $previouslts=$timestampsarray[31];
                        $threadnum=17;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[34]) {
                        $previousfts=$timestampsarray[32];
                        $previouslts=$timestampsarray[33];
                        $threadnum=18;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[36]) {
                        $previousfts=$timestampsarray[34];
                        $previouslts=$timestampsarray[35];
                        $threadnum=19;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[38]) {
                        $previousfts=$timestampsarray[36];
                        $previouslts=$timestampsarray[37];
                        $threadnum=20;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[40]) {
                        $previousfts=$timestampsarray[38];
                        $previouslts=$timestampsarray[39];
                        $threadnum=21;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[42]) {
                        $previousfts=$timestampsarray[40];
                        $previouslts=$timestampsarray[41];
                        $threadnum=22;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[44]) {
                        $previousfts=$timestampsarray[42];
                        $previouslts=$timestampsarray[43];
                        $threadnum=23;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[46]) {
                        $previousfts=$timestampsarray[44];
                        $previouslts=$timestampsarray[45];
                        $threadnum=24;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[48]) {
                        $previousfts=$timestampsarray[46];
                        $previouslts=$timestampsarray[47];
                        $threadnum=25;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[50]) {
                        $previousfts=$timestampsarray[48];
                        $previouslts=$timestampsarray[49];
                        $threadnum=26;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[52]) {
                        $previousfts=$timestampsarray[50];
                        $previouslts=$timestampsarray[51];
                        $threadnum=27;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[54]) {
                        $previousfts=$timestampsarray[52];
                        $previouslts=$timestampsarray[53];
                        $threadnum=28;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[56]) {
                        $previousfts=$timestampsarray[54];
                        $previouslts=$timestampsarray[55];
                        $threadnum=29;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[58]) {
                        $previousfts=$timestampsarray[56];
                        $previouslts=$timestampsarray[57];
                        $threadnum=30;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[60]) {
                        $previousfts=$timestampsarray[58];
                        $previouslts=$timestampsarray[59];
                        $threadnum=31;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}
                elsif ($currentfts == $timestampsarray[62]) {
                        $previousfts=$timestampsarray[60];
                        $previouslts=$timestampsarray[61];
                        $threadnum=32;
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];}

                else {
                        $previousfts="undetermined";
                        $previouslts="undetermined";
                        $threadnum="undetermined";
                        $firstthreadfts=$timestampsarray[0];
                        $firstthreadlts=$timestampsarray[1];
                }

        } #end of foreach my $fts

        #Debug
        print "determineprevthr: Called on $user and $currentfts and returning prev fts: $previousfts, lts:$previouslts and thread num. $threadnum \n";
        return ($previousfts,$previouslts,$threadnum,$firstthreadfts,$firstthreadlts);

} #End of determinepreviousthread

#Here we implement the GeoIP2 location stuff
sub pofrgeoloc {
        my $iptogeolocate=shift;
        my $versionofip=shift;

        if ( $versionofip=="4" ) {
                eval {

                        my $obj = Geo::IP2Location->open("../extensions/IP2LOCATION-LITE-DB3.BIN");

                        if (!defined($obj)) {
                                print STDERR Geo::IP2Location::get_last_error_message();
                        }

                        my $country=$obj->get_country_short($iptogeolocate);
                        my $city=$obj->get_city($iptogeolocate);

                        return $country,$city;

                } #End of eval for IPv4

        } elsif ( $versionofip=="6" ) {
                eval {
                        my $obj = Geo::IP2Location->open("../extensions/IP2LOCATION-LITE-DB3.IPV6.BIN");

                        if (!defined($obj)) {
                                print STDERR Geo::IP2Location::get_last_error_message();
                        }

                        my $country=$obj->get_country_short($iptogeolocate);
                        my $city=$obj->get_city($iptogeolocate);

                        return $country,$city;

                } #End of eval for IPv6

        } else {
                my $country="INVALIDDATADUETOIPVERSION";
                my $city = "INVALIDDATADUETOIPVERSION";

                return $country,$city;

        } #End of if ( $versionofip=="4" ) ... else


} #end of pofrgeoloc

sub processnetfile {
	#This subroutine processes the data from a network file.
	#It is called either by the filerefnet or by the fileothnet subroutine.
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
	#We also need to pass both the sprocpid from the reference and new net files.
	#The filerefnet subroutine will set the $sprocpid2 as 'EMPTY'.
	my $sprocpid=shift;
	my $sprocpid2=shift;

	my $serverip=shift;

	my ($transport,$sourceip,$sourceport,$destip,$destport,$ipversion,$pid,$nuid,$ninode,$destfqdn);

	print "Inside processnetfile: Beginning processing of file $fitopr as part of thread $thnum for user $user \n";
	#Timing issues
        my $epochref;
        my $epochplusmsec;
        my @filedata=split '#',$fitopr;
        $epochplusmsec=$filedata[0];
        my $tzone=$filedata[1];
        $tzone =~ s/.net.gz//;
        my $msecs=substr $epochplusmsec, -6;
        $epochref=substr $epochplusmsec, 0, -6;

	#Connecting to the database
        my $userdb="DBI:MariaDB:$ldb:$hostname";
        my $hostservh=DBI->connect ($userdb, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
        #Ensure that we are on the proper character set
        $hostservh->do('SET NAMES utf8mb4');

	#Beginning of TCP DATA processing
        my $table = Linux::Proc::Net::TCP->read(mnt => $netparsedir);
        for my $entry (@$table) {
                $transport="tcp";
                $sourceip=$entry->local_address;
                $sourceport=$entry->local_port;
                $destip=$entry->rem_address;
                $destport=$entry->rem_port;
                $nuid=$entry->uid;
                $ninode=$entry->inode;
                my $pid;
                my ($pidsyear,$pidsmonth,$pidsday,$pidshour,$pidsmin,$pidssec)=timestamp($epochref,$tzone);
                my $socketstr="socket:[$ninode]";

		#Are we dealing with a TCP network endpoint (not applicable to the UDP processing section  that communicates data to the POFR server?
                #If yes, we should not consider processing it.
		my @excludepid=split ',', $sprocpid;
                if ( ($destip eq $serverip and (($destport=="22" or $sourceport=="22"))) or ( $sourceip eq $serverip and (($destport=="22" or $sourceport=="22")))) {
			#Debug
                        #print "TCP data processing: Endpoint related to server IP $serverip and port 22, thus discarded \n";
                        } else {
			#Is this the primary thread?
                        my $SQLh=$hostservh->prepare("SELECT pid from $tablefilename WHERE filename='$socketstr' AND (ruid='$nuid' OR euid='$nuid') " );
                        $SQLh->execute();
                        my @pidhits=$SQLh->fetchrow_array();

                        my @ptablepidhits;
                        my @ftablepidhits;
                        #Are we the first thread?
                        if ($thnum == 1) {
				#If we are the first thread, we look into the merged fileinfo table to populate the previous table pid hits array
                                #@ptablepidhits. The pid hits array @pidhits gets populated from the current (first thread) file table.
                                $SQLh=$hostservh->prepare("SELECT pid from fileinfo WHERE filename='$socketstr' AND (ruid='$nuid' OR euid='$nuid')  " );
                                $SQLh->execute();
                                @ptablepidhits=$SQLh->fetchrow_array();
                                if ( scalar(@pidhits)=="0" && scalar(@ptablepidhits)=="0" ) {
                                        #print "thread $thnumber (should be thread 1): TCP: pid hit NOT correlated. \n";
                                        $pid="8388607"; } elsif ( scalar(@ptablepidhits) != "0" ) {
                                        $pid=$ptablepidhits[0];
                                        #print "thread $thnumber (should be thread 1): TCP: pid hit correlated from merged fileinfo table: $pid \n";
                                        } elsif ( scalar(@pidhits) != "0") {
                                        $pid=$pidhits[0];
                                        }

				} else {
					#Here we are not the first thread, we look into the previous thread table to populate the previous table pid hits array
                                        #@ptablepidhits. The file table pid hits array @ftablepidhits gets populated from the first of the 8 threads file table.                                        $SQLh=$hostservh->prepare("SELECT pid from $ptablefilename WHERE filename='$socketstr' AND (ruid='$nuid' OR euid='$nuid')  " );
                                        $SQLh->execute();
                                        @ptablepidhits=$SQLh->fetchrow_array();
                                        $SQLh=$hostservh->prepare("SELECT pid from $ftablefilename WHERE filename='$socketstr' AND (ruid='$nuid' OR euid='$nuid')  " );
                                        $SQLh->execute();
                                        @ftablepidhits=$SQLh->fetchrow_array();
				
					if ( scalar(@pidhits)=="0" && scalar(@ptablepidhits)=="0" && scalar(@ftablepidhits)=="0" ) {
                                        #print "thread $thnumber: TCP: pid hit NOT correlated. \n";
                                        $pid="8388607"; } elsif (  scalar(@ptablepidhits) != "0" ) {
                                        $pid=$ptablepidhits[0];
                                        #print "thread $thnumber: TCP: pid hit correlated from the previous thread fileinfo table: $pid \n";
                                        } elsif ( scalar(@ftablepidhits) != "0") {
                                        $pid=$ftablepidhits[0];
                                        #print "thread $thnumber: TCP: pid hit correlated from thread 1 fileinfo table: $pid \n";
                                        } elsif ( scalar(@pidhits) != "0") {
                                        $pid=$pidhits[0];
                                        #print "thread $thnumber: TCP: pid hit correlated from current thread table: $pid \n";
                                        }

                        } #end of if ($thnumber == 1)...

			if ( $sourceip =~ /\./ && $destip =~ /\./ ) { $ipversion="4"; }
                        elsif ( $sourceip =~ /\:/ && $destip =~ /\:/) { $ipversion="6"; }
                        else {
                                die "newdeltaarseproc.pl Error: Inside processnetfile: Unknown type of IP address in file $fitopr (TCP processing section). Are we getting the right type of data? \n";
                        }

                        my $digeststr1=$sourceip.$sourceport.$destip.$destport.$nuid.$ninode.$pid.$transport.$ipversion;
                        my $shanorm=sha1_hex($digeststr1);
                        $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tablenetname WHERE shasum='$shanorm' AND transport='tcp' ");
                        $SQLh->execute();
                        my @shahits=$SQLh->fetchrow_array();

			if ( $shahits[0]=="0") {
                                if (defined $ptablenetname) {
                                        #We are not the first thread here. Does the record exist in the previous thread?
                                        my $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $ptablenetname where shasum='$shanorm' AND transport='tcp' ");
                                        $SQLh->execute();
                                        my @nshahits=$SQLh->fetchrow_array();
                                        if ($nshahits[0]=="0") {
                                                #Record does not exist in the previous thread netinfo table, we need to SQL insert it.
                                                my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                                #DNS resolve only when you SQL insert to avoid DNS lookup time penalties
                                                my $resdestip=nslookup(host => "$destip", type => "PTR", timeout => "2");
                                                if (!$resdestip ) {
                                                        $destfqdn="NODESTFQDN"; } else {
                                                        $destfqdn=$resdestip;
                                                }

                                                #GeoIP2 locate
                                                my ($country,$city)=pofrgeoloc($destip,$ipversion);
                                                $destfqdn=$hostservh->quote($destfqdn);
                                                $country=$hostservh->quote($country);
                                                $city=$hostservh->quote($city);
                                                my $rows=$hostservh->do ("INSERT INTO $tablenetname(shasum,uid,pid,inode,transport,ipversion,sourceip,sourceport,destip,destport,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec,destfqdn,country,city)"
                                                . "VALUES ('$shanorm','$nuid','$pid','$ninode','$transport','$ipversion',"
                                                . "'$sourceip','$sourceport','$destip','$destport',"
                                                . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs',$destfqdn,$country,$city)" );
                                                if (($rows==-1) || (!defined($rows))) {
                                                        print "Parseproc.pl Fatal Error (inside net loop TCP processing): No net record was altered. Record $entry was not registered.\n";
                                                }} else {
                                                        #Record exists we do nothing
                                                        #print "parsenet.pl Info: TCP record exists \n";
                                                } #end of ifelse
                                } #end of if (defined..
				#Here we are part of thread number 1 so, we SQL insert the record only if it does not exist in the merged netinfo table
                                $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM netinfo WHERE shasum='$shanorm' AND transport='tcp' ");
                                $SQLh->execute();
				my @mergednetshahits=$SQLh->fetchrow_array();
                                if ( $mergednetshahits[0] == "0") {
                                        my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                        #DNS resolve only when you SQL insert to avoid DNS lookup time penalties
                                        my $resdestip=nslookup(host => "$destip", type => "PTR", timeout => "2");
                                        if (!$resdestip ) {
                                                $destfqdn="NODESTFQDN"; } else {
                                                $destfqdn=$resdestip;
                                        }

                                        #GeoIP2 locate
                                        my ($country,$city)=pofrgeoloc($destip,$ipversion);
                                        #Quote the destfqdn,country and city fields in order not to break the SQL INSERT statement
                                        $destfqdn=$hostservh->quote($destfqdn);
                                        $country=$hostservh->quote($country);
                                        $city=$hostservh->quote($city);

                                        my $rows=$hostservh->do ("INSERT INTO $tablenetname(shasum,uid,pid,inode,transport,ipversion,sourceip,sourceport,destip,destport,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec,destfqdn,country,city)"
                                        . "VALUES ('$shanorm','$nuid','$pid','$ninode','$transport','$ipversion',"
                                        . "'$sourceip','$sourceport','$destip','$destport',"
                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs',$destfqdn,$country,$city)" );
                                        if (($rows==-1) || (!defined($rows))) {
                                                print "Parseproc.pl Fatal Error: Inside processnetfile: (inside net loop TCP processing): No net record was altered. Record $entry was not registered.\n";
                                        } #End of if(($rows==-1)
                                } else {
                                        #Record exists as part of the merged netinfo table so we do nothing.
                                } #end of if ( $mergednetshahits[0] == "0")

                        } else {

                        #Record exists (as part of the first thread netinfo table so we do nothing.

                        } #end of if( $shahits)...else

                } #end of if ( ($destip==$serverip and (($destport=="22" or $sourceport=="22"))) or ( $sourceip==$serverip and (($destport=="22" or $sourceport=="22")))

        } # for my $entry... END OF TCP DATA PROCESSING
	
	#Beginning of UDP data processing
                my $tableudp = Linux::Proc::Net::UDP->read(mnt => $netparsedir);
                for my $entry (@$tableudp) {
                $transport="udp";
                $sourceip=$entry->local_address;
                $sourceport=$entry->local_port;
                $destip=$entry->rem_address;
                $destport=$entry->rem_port;
                $nuid=$entry->uid;
                $ninode=$entry->inode;
                my $pid;
                my ($pidsyear,$pidsmonth,$pidsday,$pidshour,$pidsmin,$pidssec)=timestamp($epochref,$tzone);
                my $socketstr="socket:[$ninode]";

                my $SQLh=$hostservh->prepare("SELECT pid from $tablefilename WHERE filename='$socketstr' AND (ruid='$nuid' OR euid='$nuid')  " );
                $SQLh->execute();
                my @pidhits=$SQLh->fetchrow_array();

                my @ptablepidhits;
                my @ftablepidhits;
                if ($thnum == 1) {
                        #If we are the first thread, we look into the merged fileinfo table to populate the previous table pid hits array
                        #@ptablepidhits. The file table pid hits array @pidhits gets populated from the  file table.
                        $SQLh=$hostservh->prepare("SELECT pid from fileinfo WHERE filename='$socketstr' AND (ruid='$nuid' OR euid='$nuid')  " );
                        $SQLh->execute();
                        @ptablepidhits=$SQLh->fetchrow_array();

                        if ( scalar(@pidhits)=="0" && scalar(@ptablepidhits)=="0" ) {
                                #print "thread $thnumber (should be thread 1): UDP: pid hit NOT correlated. \n";
                                $pid="8388606"; } elsif ( scalar(@ptablepidhits) != "0" ) {
                                $pid=$ptablepidhits[0];
                                #print "thread $thnumber (should be thread 1): UDP: pid hit correlated from merged fileinfo table: $pid \n";
                        } elsif ( scalar(@pidhits) != "0") {
                                $pid=$pidhits[0];
                                #print "thread $thnumber (should be thread 1): UDP: pid hit correlated from current thread table: $pid \n";
                        }

                } else {
			                       #Here we are not the first thread, we look into the previous thread table to populate the previous table pid hits array
                        # @ptablepidhits. The file table pid hits array @ftablepidhits gets populated from the first of the 8 threads file table.
                        $SQLh=$hostservh->prepare("SELECT pid from $ptablefilename WHERE filename='$socketstr' AND (ruid='$nuid' OR euid='$nuid')  " );
                        $SQLh->execute();
                        @ptablepidhits=$SQLh->fetchrow_array();
                        $SQLh=$hostservh->prepare("SELECT pid from $ftablefilename WHERE filename='$socketstr' AND (ruid='$nuid' OR euid='$nuid')  " );
                        $SQLh->execute();
                        @ftablepidhits=$SQLh->fetchrow_array();

                        if ( scalar(@pidhits)=="0" && scalar(@ptablepidhits)=="0" && scalar(@ftablepidhits)=="0" ) {
                                #print "thread $thnumber: UDP: pid hit NOT correlated. \n";
                                $pid="8388606"; } elsif (  scalar(@ptablepidhits) != "0" ) {
                                $pid=$ptablepidhits[0];
                                #print "thread $thnumber: UDP: pid hit correlated from the previous thread fileinfo table: $pid \n";
                                } elsif ( scalar(@ftablepidhits) != "0") {
                                $pid=$ftablepidhits[0];
                                #print "thread $thnumber: UDP: pid hit correlated from thread 1 fileinfo table: $pid \n";
                                } elsif ( scalar(@pidhits) != "0") {
                                $pid=$pidhits[0];
                                #print "thread $thnumber: UDP: pid hit correlated from current thread table: $pid \n";
                                }


                } #end of if ($thnumber == 1)...

		#Determining the IP version depends on the contents of the $sourceIP and $destip
                #strings. We also check what goes in the database.
                if ( $sourceip =~ /\./ && $destip =~ /\./ ) { $ipversion="4"; }
                elsif ( $sourceip =~ /\:/ && $destip =~ /\:/) { $ipversion="6"; }
                else {
                        die "newdeltaarseproc.pl Error: Inside processnetfile: (inside the net loop IP determination): Unknown type of IP address in file $fitopr (UDP processing section). Are we getting the right type of data? \n"; }

                my $digeststr1=$sourceip.$sourceport.$destip.$destport.$nuid.$ninode.$pid.$transport.$ipversion;
                my $shanorm=sha1_hex($digeststr1);
                $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $tablenetname WHERE shasum='$shanorm' AND transport='udp' ");
                $SQLh->execute();
                my @shahits=$SQLh->fetchrow_array();
		if ( $shahits[0]=="0") {
                        if (defined $ptablenetname) {
                                #We are not the first thread here. Does the recorc exists in the previous thread?
                                my $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM $ptablenetname where shasum='$shanorm' AND transport='udp' ");
                                $SQLh->execute();
                                my @nshahits=$SQLh->fetchrow_array();
                                if ($nshahits[0]=="0") {
                                        #Record does not exist in the previous thread netinfo table, we need to SQL insert it. 
                                        my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                        #DNS resolve when you SQL insert to avoid DNS lookup time penalties.
                                        my $resdestip=nslookup(host => "$destip", type => "PTR", timeout => "2");
                                        if (!$resdestip ) {
                                                $destfqdn="NODESTFQDN"; } else {
                                                $destfqdn=$resdestip;
                                        }

                                        #GeoIP2 locate
                                        my ($country,$city)=pofrgeoloc($destip,$ipversion);
                                        #Quote the destfqdn,country and city fields in order not to break the SQL INSERT statement
                                        $destfqdn=$hostservh->quote($destfqdn);
                                        $country=$hostservh->quote($country);
                                        $city=$hostservh->quote($city);

                                        my $rows=$hostservh->do ("INSERT INTO $tablenetname(shasum,uid,pid,inode,transport,ipversion,sourceip,sourceport,destip,destport,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec,destfqdn,country,city)"
                                        . "VALUES ('$shanorm','$nuid','$pid','$ninode','$transport','$ipversion',"
                                        . "'$sourceip','$sourceport','$destip','$destport',"
                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs',$destfqdn,$country,$city)" );
                                        if (($rows==-1) || (!defined($rows))) {
                                                print "newdeltaparseproc.pl Fatal Error: Inside processnetfile: (inside net loop UDP processing): No net record was altered. Record $entry was not registered.\n";
                                        }

                                } else {
                                        #Record exists we do nothing
                                }

                        } #end of if (defined...

                        #Here we are part of thread number 1 so, we SQL insert the record only if it does not exist in the merged netinfo thread.
                        $SQLh=$hostservh->prepare("SELECT COUNT(*) FROM netinfo WHERE shasum='$shanorm' AND transport='udp' ");
                        $SQLh->execute();
                        my @mergednetshahits=$SQLh->fetchrow_array();
			if ( $mergednetshahits[0] == "0") {
                                        my ($cyear,$cmonth,$cday,$chour,$cmin,$csec)=timestamp($epochref,$tzone);
                                        #DNS resolve when you SQL insert to avoid DNS lookup time penalties.
                                        my $resdestip=nslookup(host => "$destip", type => "PTR", timeout => "2");
                                        if (!$resdestip ) {
                                                $destfqdn="NODESTFQDN"; } else {
                                                $destfqdn=$resdestip;
                                        }

                                        #Quote the destfqdn in order not to break the SQL INSERT statement
                                        $destfqdn=$hostservh->quote($destfqdn);
                                        #GeoIP2 locate
                                        my ($country,$city)=pofrgeoloc($destip,$ipversion);

                                        #Quote the destfqdn,country and city fields in order not to break the SQL INSERT statement
                                        $destfqdn=$hostservh->quote($destfqdn);
                                        $country=$hostservh->quote($country);
                                        $city=$hostservh->quote($city);


                                        my $rows=$hostservh->do ("INSERT INTO $tablenetname(shasum,uid,pid,inode,transport,ipversion,sourceip,sourceport,destip,destport,tzone,cyear,cmonth,cday,chour,cmin,csec,cmsec,destfqdn,country,city)"
                                        . "VALUES ('$shanorm','$nuid','$pid','$ninode','$transport','$ipversion',"
                                        . "'$sourceip','$sourceport','$destip','$destport',"
                                        . "'$tzone','$cyear','$cmonth','$cday','$chour','$cmin','$csec','$msecs',$destfqdn,$country,$city)" );
                                        if (($rows==-1) || (!defined($rows))) {
                                                print "newdataparseproc.pl Fatal Error: Inside processnetfile: (inside the net loop UDP section): No process record was altered. Record $entry was not registered.\n";
                                        } #end of if (($rows==-1) 

                                } else {
                                        #Record exists as part of the merged netinfo table so we do nothing.
                                } #end of if ( $mergednetshahits[0] == "0") ... else


                         } else {
                        #Record exists as part of the current netinfo table of thread 1 so we do nothing.

                         }#end of if ( $shahits[0]=="0") else....(UDP Section)  

        } #End of UDP data processing for my for my $entry (@$tableudp) 

	#Eventually unlink the file that was processed
        unlink "$threadspecificpath/dev/shm/$fitopr" or warn "newdeltaparseproc.pl Warning: Inside processnetfile: Could not unlink net file /home/$threadspecificpath/dev/shm/$fitopr: $!";
        $hostservh->disconnect;

} #end of subroutine processnetfile


1;
