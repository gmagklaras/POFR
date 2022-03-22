#!../pofrperl/bin/perl -w -I ../pofrperl/lib/5.34.0/x86_64-linux -I ../pofrperl/lib/5.34.0
###
use lib '../pofrperl/lib/site_perl/5.34.0';

use strict;
use warnings;
use DBI;
use Time::HiRes qw(usleep clock_gettime gettimeofday clock_getres CLOCK_REALTIME ITIMER_REAL ITIMER_VIRTUAL ITIMER_PROF ITIMER_REALPROF);
use IO::File;
use Getopt::Long;
use DateTime;
use DateTime::Format::Duration;



my $usertoprocess=shift;

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

	my $datasource="DBI:MariaDB:$ldb:$hostname";
	my $hostservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
	$hostservh->do('SET NAMES utf8mb4');

	$SQLh=$hostservh->prepare("show tables LIKE 'archpsinfo%'");
	$SQLh->execute();

	my @rangehits;
	while ( my $row=$SQLh->fetchrow()) {
		push (@rangehits,$row);
	}

	#Now we have to get the dates and times of the first and last piece of data
        #Select the first row of the first archpsinfo table
        my ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec);
        my ($lyear,$lmonth,$lday,$lhour,$lmin,$lsec,$lmsec);

        my $SQLh;
        $SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $rangehits[0] LIMIT 1" );
        $SQLh->execute();
        my @pdata=$SQLh->fetchrow_array();

        #Listifying the @pdata array
        ($pyear,$pmonth,$pday,$phour,$pmin,$psec,$pmsec)=@pdata[0..$#pdata];

        #Then select the last record of the LAST archpsinfo table
        $SQLh=$hostservh->prepare("SELECT cyear,cmonth,cday,chour,cmin,csec,cmsec from $rangehits[-1] ORDER BY psentity DESC LIMIT 1" );
        $SQLh->execute();
        my @ldata=$SQLh->fetchrow_array();

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
} #End of find_data_range subroutine

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

#sub get_requested_data_time_range: Grabs a list of archtables from a requested data time range
#ACCEPTS: a username and a list of requested data
#RETURNS: A list of arch tables for the requested data range, if the data exists
#	  A empty list of arrays if the data does not exist or if there is another problem with the query 
sub get_requested_data_time_range {
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

	my @targetprocessarchtables;
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

        	my $datasource="DBI:MariaDB:$ldb:$hostname";
        	my $hostservh=DBI->connect ($datasource, $dbusername, $dbpass, {RaiseError => 1, PrintError => 1});
       		$hostservh->do('SET NAMES utf8mb4');

		my @myparchtables=$hostservh->tables('', $ldb, 'archpsinfo%', 'TABLE');
		my @myfarchtables=$hostservh->tables('', $ldb, 'archfileinfo%', 'TABLE');
        	my @mynarchtables=$hostservh->tables('', $ldb, 'archnetinfo%', 'TABLE');

		
		my @finalparchtables;

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

		
			#Are the requested rldata greater or equally recent than the stored dldata?
			#If yes, push the table into the finalparchtables array
        		my $dldata = DateTime->new(
                		year      => $lyear,
                		month     => $lmonth,
                		day       => $lday,
                		hour      => $lhour,
                		minute    => $lmin,
                		second    => $lsec,
        		);

        		my $rldata = DateTime->new(
                		year      => $rlyear,
                		month     => $rlmonth,
                		day       => $rlday,
                		hour      => $rlhour,
                		minute    => $rlmin,
                		second    => $rlsec,
        		);

        		my $ldelta = $rldata->subtract_datetime($dldata);

        		my $lstatus = DateTime::Format::Duration->new(pattern => '%Y,%m,%e,%H,%M,%S');

        		my @cld=split(',', $lstatus->format_duration($ldelta));
        		my $negcld=0;
        		foreach (@cld) {
                		if (!($_ >=0)) { $negcld=$negcld+1; };
        		}
			
			print "Debug: negcpd is negcpd and negcld is $negcld \n";

        		#Finally conclude if we do not have negative delta on either of the two checks we are OK
       			#otherwise we are NOT
        		if ( $negcld=="0") {
                		push(@finalparchtables,$currentptable);
        		} else {
				##Do nothing
        		}

		     

		} #End of foreach my $currentptable (@@myparchtables)
	
		print "Debug: finalparchtables is  @finalparchtables \n";
		return @finalparchtables;

	} elsif ( $answer eq "False") {
		#return an empty list of arrays

	} else {
		#return an empty list of arrays
	}


} #End of get_requested_data_time_range	


my ($pday,$pmonth,$pyear,$phour,$pmin,$psec,$lday,$lmonth,$lyear,$lhour,$lmin,$lsec)=find_data_time_range("bef5f0350b4a3395896f14d2926abcf5");

my $answer=check_requested_data_time_range("bef5f0350b4a3395896f14d2926abcf5","02","02","2022","23","02","21","20","03","2022","02","55","44");
print "Checking the requested date range returns : $answer \n";

my $answer2=get_requested_data_time_range("bef5f0350b4a3395896f14d2926abcf5","19","03","2022","23","02","21","20","03","2022","02","58","42");


print "Getting the requested data time range returns: $answer2 \n";
print "$pday,$pmonth,$pyear,$phour,$pmin,$psec,$lday,$lmonth,$lyear,$lhour,$lmin,$lsec";

