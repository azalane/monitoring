#!/usr/bin/env perl

########################################################################
# About this script
#
# This script will check the status of a VM on 
# Amazon web service - Elastic Compute Cloud  (AWS - EC2)
# Use Paws perl module to connect on AWS API request
########################################################################
#  Original version written by azalane
#  20170627 : original version
########################################################################

my $release = "20170627.scz" ;

use strict;
use warnings;

use File::Basename;
use Getopt::Long qw(:config no_ignore_case bundling); 
use Paws;
use Paws::Credential::Explicit; 
use Paws::Exception;
use lib '.';
use lib "/usr/lib/nagios/plugins";

use vars qw($PROGNAME $VERSION);

use utils qw(%ERRORS);


$PROGNAME = basename($0);
$VERSION = 'Revision: 1.0.'.$release;

my ($opt_h, $opt_v);
my ($instance_id,$aws_region,$aws_access_key_id,$aws_secret_access_key,$modules,$hostname);
my ($status, @modules);

# Get param
GetOptions( "h"   => \$opt_h, "help" => \$opt_h,
            "I=s" => \$instance_id, "instanceid=s" => \$instance_id,
            "R=s" => \$aws_region, "region=s" => \$aws_region,
			"K=s" => \$aws_access_key_id, "key=s" => \$aws_access_key_id,
            "S=s" => \$aws_secret_access_key, "secret=s" => \$aws_secret_access_key,
            "M=s" => \$modules, "module=s" => \$modules,
            "H=s" => \$hostname, "hostname=s" => \$hostname,			
			"v"   => \$opt_v, "version" => \$opt_v,
) or exit $ERRORS{'UNKNOWN'};

#Help or version
if ($opt_h) {print_help(); exit $ERRORS{'OK'};}

my ($sec,$min,$hour,$day,$month,$yr19,@rest) =   localtime(time);
my $DT=sprintf("%04d-%02d-%02d %02d:%02d:%02d", $yr19+1900, ($month+1), $day , $hour, $min, $sec);

if ($opt_v)
{
        print "OK OA DATE='$DT' VAL='".$ERRORS{'OK'}."' MSG='$VERSION - no check performed.'\n";
        exit $ERRORS{'OK'};
}
#check required param
if( !defined($instance_id) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='Instance ID (-I) must be defined.'\n";
        exit $ERRORS{'UNKNOWN'};
}
if( !defined($aws_region) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='AWS Region (-R) must be defined.'\n";
        exit $ERRORS{'UNKNOWN'};
}
if( !defined($aws_access_key_id) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='AWS access key id (-K) must be defined.'\n";
        exit $ERRORS{'UNKNOWN'};
}
if( !defined($aws_secret_access_key) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='AWS secret access key (-S) must be defined.'\n";
        exit $ERRORS{'UNKNOWN'};
}
if( !defined($modules) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='Module to check (-M) must be defined.'\n";
        exit $ERRORS{'UNKNOWN'};
}
elsif ( $modules !~ /(?:instancestatus)/i )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='Invalid module name (-M).'\n";
        exit $ERRORS{'UNKNOWN'};
}

#Connect to AWS EC2
#Declare credentials
my $cred_provider = Paws::Credential::Explicit->new(
    access_key => $aws_access_key_id,
    secret_key => $aws_secret_access_key,
);
#Declare EC2 Connection
my $ec2 = Paws->service('EC2', credentials => $cred_provider, region => $aws_region);

#Check modules
@modules = split(/,|;|\|/, $modules);

foreach $modules (@modules)
{
        if( $modules =~ /instancestatus/i )
        {
                $status = check_instancestatus();
        }
}

if( $status == 1 )
{
        print "OK OA DATE='$DT' VAL='".$ERRORS{'OK'}."' MSG='$modules OK.'\n";
        exit $ERRORS{'OK'};
}

# Sub check instance status
sub check_instancestatus
{
	#Get instance status for id 
	my $result;
	eval {$result = $ec2->DescribeInstanceStatus( InstanceIds => [ $instance_id ]);};
	
	if ($@){
		if ($@->code eq 'AuthFailure') {
			print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='Can't authenticate on AWS. Verify your credentials'\n";
			exit $ERRORS{'CRITICAL'};
		}
		elsif ($@->code eq 'InvalidInstanceID.Malformed') {
			print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='Checked instance not exist. Verify your instance ID (-I)'\n";
			exit $ERRORS{'CRITICAL'};
		}
		elsif ($@->code eq 'ConnectionError') {
			print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='Can't connect to Amazon. Verify Internet connection or Region parameter (-R)'\n";
			exit $ERRORS{'CRITICAL'};
		}
		else {
			print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='Unknow error during instance check'\n";
			exit $ERRORS{'CRITICAL'};
		}
	}
	if( !defined($result->InstanceStatuses->[0])){
        print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='Instance AWS is down'\n";
		exit $ERRORS{'CRITICAL'};
	}
	else {
		my $InstanceStatus = $result->InstanceStatuses->[0]->InstanceStatus->Status ;
		my $SystemStatus = $result->InstanceStatuses->[0]->SystemStatus->Status  ;
		if ($InstanceStatus ne "ok") {
			print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='Instance Status Error'\n";
			exit $ERRORS{'CRITICAL'};
		} 
		elsif ($SystemStatus ne "ok") {
			print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='System Status Error'\n";
			exit $ERRORS{'CRITICAL'};
		}
		else {
			return 1
		}
	}
			
}

#sub Usage
sub print_usage
{
        print<<EOT;
Usage:  
$PROGNAME -I <EC2 Instance ID> -H <Hostname> -R <AWS Regions> -K <AWS access key id> -S <AWS secret acces key> -M <module to check> 

$PROGNAME -v | --version (Currently $VERSION)

$PROGNAME -h | --help
EOT
}

#sub Help
sub print_help
{
        print <<EOT;
$PROGNAME
$VERSION

This script will check an Amazon EC2 Instance
It use Amazon API Request, so be careful to billing

EOT
print_usage();
print<<EOT;

-------------------------------------------------------------
Required
		
-I | --instanceid <EC2 Instance ID>
Amazon EC2 Instance to connect : format must be : i-xxxxxxxxxxxxxxxxx
		
-H | --hostname <Hostname or IP>
Unused. Hostname is a default option sent by Nagios plugins system

-R | --region <AWS Regions>
The AWS region where your instance is running : You can find it on AWS EC2 help

-K | --key <AWS access key id>
Your AWS acces key ID

-S | --secret <AWS secret acces key>
Your AWS secret acces key

-M | --module <module to check>
Specify module to check. May be one of :
    instancestatus (Check state of the EC2 instance infrastructure and system) 

	
-------------------------------------------------------------
Optional


EOT
}

