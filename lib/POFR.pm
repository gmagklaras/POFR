# POFR.pm: A Perl module that contains subroutine definitions for handling a range of functions 
# such as time management, data subset extraction, authentication and database connection functionality  

#POFR - Penguin OS Forensic (or Flight) Recorder - 
#A program that collects stores and organizes for further analysis process execution, file access and network/socket endpoint data from the Linux Operating System 
#and derivatives.
#Copyright (C) 2022 Georgios Magklaras

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

our @ISA= qw( Exporter );

#Control what we export by default
our @EXPORT = qw( getdbauth timestamp table_exists find_data_time_range check_requested_data_time_range date_is_later_than date_is_earlier_than get_requested_data_from_time_range );


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

sub timestamp {
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
} #end of timestamp subroutine

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
		return (\@targetprocarchtables, \@targetfilearchtables, @targetnetarchtables);

	} elsif ( $answer eq "False") {
		#Here we have had no data in range, because check_requested_data_time_range()
		#claimed the request was out of range.
	        push (@targetprocarchtables, "NODATA");
		push (@targetfilearchtables, "NODATA");
		push (@targetnetarchtables, "NODATA");
		return (\@targetprocarchtables, \@targetfilearchtables, @targetnetarchtables);

	} else {
		#Here we probably have a malformed query, because check_requested_data_time_range()
                #claimed something else was wrong.
		push (@targetprocarchtables, "ERROR");
                push (@targetfilearchtables, "ERROR");
                push (@targetnetarchtables, "ERROR");
                return (\@targetprocarchtables, \@targetfilearchtables, @targetnetarchtables);

	}



} #End of subroutine get_requested_data_time_range


1;
