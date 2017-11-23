#!/usr/bin/perl -w

########################################################################
# Original version written by azalane
#
# This script is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This script is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# About this script :
#
# This script will check the status ACME Packet SBC (Oracle) via SNMP.
#
########################################################################
# 20171116 azalane - Initial version
# 20171123 azalane - Add check state of redundancy
########################################################################

my $release = "r20171123.scz" ;

#######################################################################
# OID To Check
use constant NumberLicence	=> '.1.3.6.1.4.1.9148.3.2.1.1.10.0';
use constant MemoryUsed	=> '.1.3.6.1.4.1.9148.3.2.1.1.2.0';
use constant SystemHealth	=> '.1.3.6.1.4.1.9148.3.2.1.1.3.0'; 
use constant CurrentSessions	=> '.1.3.6.1.4.1.9148.3.2.1.1.5.0'; 
use constant CurrentCalls	=> '.1.3.6.1.4.1.9148.3.2.1.1.6.0'; 
use constant SbcMode	=> '.1.3.6.1.4.1.9148.3.2.1.1.4.0'; 
use constant AverageCPU	=> '.1.3.6.1.4.1.9148.3.2.1.1.1.0'; 
use constant UnitCpuUse	=> '.1.3.6.1.4.1.9148.3.17.1.1.10.1';
#######################################################################

use strict;
use Getopt::Long qw(:config no_ignore_case bundling);
use File::Basename;
use vars qw($PROGNAME $VERSION);
use lib '.';
use lib '/usr/local/nagios/OA_nagios/plugins';
use utils qw(%ERRORS);
use Net::SNMP;

$PROGNAME = basename($0);
$VERSION = 'Version: 1.0 '.$release;
$ENV{LC_ALL} = 'POSIX';

my ($opt_h, $opt_c, $opt_w, $opt_v);
our ($host, $modes, $snmp_timeout, $snmp_retries, $snmp_community,$redundancy);
my ($status, @modes, @critical, @warning );
our ($mode, $critical, $warning);

GetOptions( "h"   => \$opt_h, "help" => \$opt_h,
            "w=s" => \$opt_w, "warning=s"  => \$opt_w,
            "c=s" => \$opt_c, "critical=s" => \$opt_c,
            "m=s" => \$modes, "mode=s" => \$modes,
            "H=s" => \$host, "host=s" => \$host,
			"R=s" => \$redundancy, "redundancy=s" => \$redundancy,
            "C=s" => \$snmp_community, "snmp_community=s" => \$snmp_community,
            "t=i" => \$snmp_timeout, "snmp_timeout=i" => \$snmp_timeout,
            "r=i" => \$snmp_retries, "snmp_retries=i" => \$snmp_retries,
            "v"   => \$opt_v, "version" => \$opt_v,
) or exit $ERRORS{'UNKNOWN'};


if ($opt_h) {print_help(); exit $ERRORS{'OK'};}

my ($sec,$min,$hour,$day,$month,$yr19,@rest) =   localtime(time);
my $DT=sprintf("%04d-%02d-%02d %02d:%02d:%02d", $yr19+1900, ($month+1), $day , $hour, $min, $sec);

if ($opt_v)
{
        print "OK OA DATE='$DT' VAL='".$ERRORS{'OK'}."' MSG='$VERSION - no check performed.'\n";
        exit $ERRORS{'OK'};
}

if( !defined($host) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='host (-H) must be defined.'\n";
        exit $ERRORS{'UNKNOWN'};
}

if( !defined($modes) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='mode (-m) must be defined.'\n";
        exit $ERRORS{'UNKNOWN'};
}
elsif ( $modes !~ /(?:memory_used)|(?:licence_used)|(?:health_score)|(?:current_sessions)|(?:current_calls)|(?:sbc_mode)|(?:cpu_load_m)|(?:cpu_load_u)/i )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='invalid mode (-m).'\n";
        exit $ERRORS{'UNKNOWN'};
}

$snmp_timeout = 10 unless defined($snmp_timeout);
$snmp_retries = 0 unless defined($snmp_retries);

if( !defined($snmp_community) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'UNKNOWN'}."' MSG='community must be specified.'\n";
        exit $ERRORS{'UNKNOWN'};
}

my ($session, $error, @args);

push(@args, (
        '-version'       => "2c",
        '-hostname'      => $host,
        '-timeout'       => $snmp_timeout,
        '-retries'       => $snmp_retries,
        '-community' => $snmp_community
        ) );

($session, $error) = Net::SNMP->session( @args );

if( !defined($session) )
{
        print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='no SNMP session for host $host.'\n";
        exit $ERRORS{'CRITICAL'};
}

@modes = split(/,|;|\|/, $modes);
if( $#modes >=0 )
{
        @warning = split(/,|;|\|/, $opt_w) if( defined($opt_w) );
        @critical = split(/,|;|\|/, $opt_c) if( defined($opt_c) );
}

foreach $mode (@modes)
{
        if( $#warning >=0 )
        {
                $warning = shift @warning;
        }
        else
        {
                $warning = undef;
        }
        if( $#critical >=0 )
        {
                $critical = shift @critical;
        }
        else
        {
                $critical = undef;
        }

        if( $mode =~ /memory_used/i )
        {
				$status = check_simple($session, $warning, $critical,MemoryUsed,'% of memory used');
        }
        elsif( $mode =~ /licence_used/i )
        {
                $status = check_simple($session, $warning, $critical,NumberLicence,'% of licences used');
        }
        elsif( $mode =~ /health_score/i )
        {
				$status = check_health($session, $warning, $critical);
        }
        elsif( $mode =~ /current_sessions/i )
        {
				$status = check_simple($session, $warning, $critical,CurrentSessions,' current sessions used');
        }
        elsif( $mode =~ /current_calls/i )
        {
				$status = check_simple($session, $warning, $critical,CurrentCalls,' call per second');
        }
        elsif( $mode =~ /sbc_mode/i )
        {
				$status = check_mode($session, $warning, $critical);
        }
        elsif( $mode =~ /cpu_load_m/i )
        {
				$status = check_simple($session, $warning, $critical,AverageCPU,'% of CPU used');
        }
		elsif( $mode =~ /cpu_load_u/i )
        {
				$status = check_cpu($session, $warning, $critical);
        }
}

$session->close();

if( $status == 1 )
{
        print "OK OA DATE='$DT' VAL='".$ERRORS{'OK'}."' MSG='$modes OK.'\n";
        exit $ERRORS{'OK'};
}

#######################################################################
#	SUBS CHECK SIMPLE OID
#######################################################################
sub check_simple
{
        my ($session, $thrw, $thrc,$oid_param,$message) = @_;
        my @oids = (
                $oid_param,
        );

        my $results = $session->get_request('-varbindlist' => \@oids);

        if( !defined($results) )
        {
                print "KO OA - DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : invalid response from host.'\n";
                exit $ERRORS{'CRITICAL'};
        }
        my $describ = $results->{$oid_param};
        if( $describ eq 'noSuchObject' )
        {
                print "KO OA - DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : object not found for host.'\n";
                exit $ERRORS{'CRITICAL'};
        }

        if ( $describ > $thrc )
        {
                print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : CRITICAL - $describ$message.'\n";
                exit $ERRORS{'CRITICAL'};
        }
        elsif ( defined($thrw) && $describ > $thrw )
        {
                print "KO OA DATE='$DT' VAL='".$ERRORS{'WARNING'}."' MSG='$mode : WARNING - $describ$message.'\n";
                exit $ERRORS{'WARNING'};
        }
        return 1;
}
#######################################################################
#	SUBS CHECK HEALTH
#######################################################################
sub check_health
{
        my ($session, $thrw, $thrc) = @_;
        my @oids = (
               SystemHealth,
        );

        my $results = $session->get_request('-varbindlist' => \@oids);

        if( !defined($results) )
        {
                print "KO OA - DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : invalid response from host.'\n";
                exit $ERRORS{'CRITICAL'};
        }
        my $describ = $results->{&SystemHealth};
        if( $describ eq 'noSuchObject' )
        {
                print "KO OA - DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : object not found for host.'\n";
                exit $ERRORS{'CRITICAL'};
        }

        if ( $describ < $thrc )
        {
                print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : CRITICAL - $describ% of health.'\n";
                exit $ERRORS{'CRITICAL'};
        }
        elsif ( defined($thrw) && $describ < $thrw )
        {
                print "KO OA DATE='$DT' VAL='".$ERRORS{'WARNING'}."' MSG='$mode : WARNING - $describ% of health.'\n";
                exit $ERRORS{'WARNING'};
        }
        return 1;
}
#######################################################################
#	SUBS CHECK MODE
#######################################################################
sub check_mode
{
        my ($session, $thrw, $thrc,) = @_;
        my @oids = (
                SbcMode,
        );
		
		my @coresp = ('unknown','initial','active','standby','outOfService','unassigned','activePending','standbyPending','outOfServicePending','recovery');
        my $results = $session->get_request('-varbindlist' => \@oids);

        if( !defined($results) )
        {
                print "KO OA - DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : invalid response from host.'\n";
                exit $ERRORS{'CRITICAL'};
        }
        my $describ = $results->{&SbcMode};
        if( $describ eq 'noSuchObject' )
        {
                print "KO OA - DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : object not found for host.'\n";
                exit $ERRORS{'CRITICAL'};
        }

        if ( $describ < 2 or $describ > 3 )
        {
                print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : CRITICAL - SBC is in $coresp[$describ] mode.'\n";
                exit $ERRORS{'CRITICAL'};
        }
		#Clustering mode get state of other sbc
		if ( defined($redundancy) )
		{
			#Gest information of the second SBC
			my ($session2, $error2, @args2);
			push(@args2, (
					'-version'       => "2c",
					'-hostname'      => $redundancy,
					'-timeout'       => $snmp_timeout,
					'-retries'       => $snmp_retries,
					'-community' => $snmp_community
					) );

			($session2, $error2) = Net::SNMP->session( @args2 );
			if( !defined($session2) )
			{
					print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='no SNMP session for the other member of cluster : $redundancy'\n";
					exit $ERRORS{'CRITICAL'};
			}
			my $results2 = $session2->get_request('-varbindlist' => \@oids);
			if( !defined($results) )
			{
					print "KO OA - DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : invalid response from the other member of cluster : $redundancy'\n";
					exit $ERRORS{'CRITICAL'};
			}
			my $describ2 = $results2->{&SbcMode};
			if( $describ2 eq 'noSuchObject' )
			{
					print "KO OA - DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : object not found for the other member of cluster : $redundancy'\n";
					exit $ERRORS{'CRITICAL'};
			}
			#Check if state of redundancy is good
			if ( $describ2 eq $describ )
			{
					print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : CRITICAL - All members of cluster are in $coresp[$describ] mode.'\n";
					exit $ERRORS{'CRITICAL'};
			}
			elsif ( $describ2 !=2 and $describ !=2)
			{
					print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : CRITICAL - No members of cluster are in Active mode.'\n";
					exit $ERRORS{'CRITICAL'};			
			}
			else 
			{
				print "OK OA DATE='$DT' VAL='".$ERRORS{'OK'}."' MSG='$mode : OK - SBC $host is $coresp[$describ] and SBC $redundancy is $coresp[$describ2].'\n";
				exit $ERRORS{'OK'};
			}

		}
		print "OK OA DATE='$DT' VAL='".$ERRORS{'OK'}."' MSG='$mode : OK - SBC $host is $coresp[$describ].'\n";
        exit $ERRORS{'OK'};
		
}
#######################################################################
#	SUBS CHECK CPU
#######################################################################

#use constant UnitCpuUse	=> '.1.3.6.1.4.1.9148.3.17.1.1.10.1';
use constant UnitCpuExist            => '.1.3.6.1.4.1.9148.3.17.1.1.10.1.1.1';
use constant UnitCpuState             => '.1.3.6.1.4.1.9148.3.17.1.1.10.1.1.2';

sub check_cpu
{
        my ($session, $thrw, $thrc) = @_;
        my ($status, $results) = getTable($session, UnitCpuUse);
        my (@indexes, $ref);

        if( $status != 1 )
        {
                print "KO OA DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : CRITICAL - Invalid response from host: $results.'\n";
                exit $ERRORS{'CRITICAL'};
        }
		
		#Cpu list
        my $pat = '^'.&UnitCpuExist.'\.(\d+)$';

        foreach $ref ( keys (%{$results}) )
        {
                if( $ref =~ /$pat/ )
                {
                        if( defined($1) )
                        {
                                push @indexes, $1;
                        }
                }
        }
        # no cpu found !
        if( $#indexes == -1 )
        {
                print "KO DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : CRITICAL - No CPU found !'\n";
                exit $ERRORS{'CRITICAL'};
        }

		#Cpu value
        foreach my $idx (@indexes)
        {
                next if( $results->{&UnitCpuExist.'.'.$idx} == 2 );
                $status = unpack("c*", $results->{&UnitCpuState.'.'.$idx} );
                if ( $status > $thrc )
                {
                        print "KO DATE='$DT' VAL='".$ERRORS{'CRITICAL'}."' MSG='$mode : CRITICAL - CPU $idx : $status% of use.'\n";
                        exit $ERRORS{'CRITICAL'};
                }
                elsif ( defined($thrw) && $status > $thrw )
                {
                        print "KO DATE='$DT' VAL='".$ERRORS{'WARNING'}."' MSG='$mode : WARNING -CPU $idx : $status% of use.'\n";
                        exit $ERRORS{'WARNING'};
                }
        }
        return 1;
}

#######################################################################


sub getTable
{
        my( $session, $base_OID ) =@_;
        my $response;

        $response = $session->get_table( $base_OID );
        if( !defined($response) )
        {
                my $error = $session->error();
                if( $error =~ /^No response/ )
                {
                        return -1,"SNMP session for $host not responding!";
                }
                else
                {
                        return 0, "no response from $host for $base_OID" ;
                }
        }
        return( 1, $response );
}
#######################################################################
# print help 
sub print_help {

print <<EOT;

------------------------------------------------------------------------------

       This script will check the status ACME Packet SBC (Oracle) via SNMP.
  
------------------------------------------------------------------------------
USAGE :
       $0 -m | --mode <module to check>  
       $0 -v | --version
       $0 -h | --help

------------------------------------------------------------------------------

-H | --host <host>
        Host to connect to : format can be hostname or ip address follown by ':' and port number.

-m | --mode <MODE>
        Specify the module to check. May be one of :
            memory_used : Memory used by SBC
			licence_used : Percentage of licensed sessions currently in progress.
			health_score : System health percentage.0>>100, 100% is healthiest. Alert if health_score is under threshold. 
			current_sessions : Number of Global Concurrent Sessions.
			current_calls : Number of current global call per second.
			sbc_mode : Running mode of SBC. Active(2) et Standby(3) are OK, Other mode are KO.
			cpu_load_m : global average CPU used. Average of all CPU used on out of limit to return bad status.
			cpu_load_u : unitary average CPU used. One or more CPU out of limit to return bad status.

-R | --redundancy <IP>
        Ip address of the other member of cluster. Use it only with check mode "sbc_mode". 
		If this parameter is specified, sbc_mode check if the host is in active or standby mode, if them two SBC 
		aren't in the same mode, and if there is at least one SBC in active mode.
		If isn't specified, sbc_mode is in classical.

-c | --critical
        Exit with CRITICAL status if the monitored value is more than the critical value.
        No default value.

-w | --warning
        Exit with WARNING status if the monitored value is more than the warning value.
        No default value.

-C | --snmp_community <value>
        SNMP Community.
        No default value.

-t | --snmp_timeout <value>
		set the request timeout (in seconds) for SNMP session be established.
		Default value: 10

-r | --snmp_retries <value>
        set the number of retries after the request is timed out.
        Default value: 0

-v | --version
		Dispolay the version.
		current is $VERSION

-h | --help
		Show this help.

EOT
}
