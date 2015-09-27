#!/usr/bin/perl

=head1 SSL – Swiss SSL Lawn

=head1 DESCRIPTION

This script allows to audit SSL security settings of web servers.

This includes :

=over

=item *

SSL protocols and ciphers verification

=item *

x509 Certificate inspection

=item *

HTTPs redirection and web content (social network, Server Type and flash)

=back


=head1 AUTEUR

Ameti Behar

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

use strict;
use warnings;

# --- Import Perl Module used in the script

use HTTP::Tiny;
use Getopt::Long;
use XML::LibXML;
use XML::Dumper;
use XML::Simple;
use Data::Dumper;
use IO::Socket::SSL;
use Socket;
use Config::IniFiles;
use Time::gmtime;
use Time::ParseDate;
use Log::Log4perl;
use Mozilla::CA;
use threads;

# --- Import created module used in the script

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Libs';
use CheckPort qw(check_port);
use CheckHostName qw(check_hostname);
use CheckInit qw(check_init);
use CheckProtocolCipher qw(check_protocol_cipher);
use GetCertDetails qw(get_cert_details);
use CheckContent qw(check_content);
use ComputeScore qw(compute_score compute_final_result);
use SaveToXML qw(saveToxml);

# --- Import created classes used in the script
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Classes';
use Survey;

# --- Initialize logging info message for debug
my $log_conf = q(
   log4perl.rootLogger              = INFO, LOG1
   log4perl.appender.LOG1           = Log::Log4perl::Appender::File
   log4perl.appender.LOG1.filename  = ./Log/logfile.log
   log4perl.appender.LOG1.mode      = append
   log4perl.appender.LOG1.layout    = Log::Log4perl::Layout::PatternLayout
   log4perl.appender.LOG1.layout.ConversionPattern = %d %p %m %n
);
Log::Log4perl::init(\$log_conf);
my $logger = Log::Log4perl->get_logger();


# --- "Module" used in the script
sub get_time {

    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
    my $nice_timestamp = sprintf ( "%02d.%02d.%04d",$mday,$mon+1,$year+1900);
    return $nice_timestamp;
}

# --- Check with threads
sub check{
	my ( $audit , $xmlListe, $iniFile ) = @_;

	$audit->set_ip(inet_ntoa(inet_aton($audit->get_hostName())));

	my $set_ssl  = threads->new(\&check_protocol_cipher, $audit->get_hostName(), $audit->get_port(), $iniFile);
	my $set_cert = threads->new(\&get_cert_details, $audit->get_hostName(), $audit->get_port(), $xmlListe);
	my $set_content = threads->new(\&check_content, $audit->get_hostName(), $audit->get_port());

	$audit->set_ssl($set_ssl->join());
	$audit->set_cert($set_cert->join());
	$audit->set_content($set_content->join());

	return $audit
}

# --- Script varaibles

my $xmlListe = "BDD/hostsList.xml";
my $protoCipherFile = "ini/ProtoCipher.ini";
my @moduleList =("HTTP::Tiny","Getopt::Long","XML::LibXML","XML::Dumper","XML::Simple",
		"Data::Dumper","IO::Socket::SSL","Socket","Net::SSLeay","Config::IniFiles",
		"Time::gmtime","Time::ParseDate","Log::Log4perl","LWP::UserAgent","HTTP::Response",
		"File::stat");
my $survey = {};
my $hosts;
my $start = time;

$logger->info("############## - Start Audit.pl the " . get_time() . " - ##############");

# --- Script test init

$hosts = check_init($xmlListe, $protoCipherFile, \@moduleList);
my $i = 0;
# --- Main script
foreach my $host (@$hosts) {
	
	my $audit = Survey->new();
	$audit->set_hostName($host->firstChild->data);
	$audit->set_date(get_time());
	$audit->set_id($host->getAttribute("ID"));
	$audit->set_hostType($host->getAttribute("type"));
	$audit->set_port($host->getAttribute("port"));	

	if ( check_port( $audit ) ) {
		if ( check_hostname( $audit ) ) {
			$audit->set_grade("Temp");				
			$audit->set_trusted("Oui");
			$audit = check( $audit, $xmlListe , $protoCipherFile);
			$audit = compute_final_result($audit);
		}# if !check_hostname
		else{
			# If host name don't match give F result
			$audit->set_trusted("Hostname missmatch");
			# Check protocol and cipher
			$audit = check( $audit, $xmlListe, $protoCipherFile );
			$audit = compute_final_result($audit);
			$audit->set_grade("F");
			if(!defined($audit->get_cert())){
				$audit->set_grade("Z");
				my $cert = {};
				$cert->{pubkey_bits} = 0;
				$audit->set_cert($cert);
			}
		}
		
	}# if check_port
	else{
		my $cert = {};
		$cert->{pubkey_bits} = 0;
		$audit->set_grade("Z");
		$audit->set_result(0);
		$audit->set_trusted("Non");
		$audit->set_cert($cert);
	}
	$survey->{$i} = $audit;
	$i++;
	$logger->info("----------------------------------------------------------");
}# foreach host
my $duration = time - $start;
saveToxml($survey);
undef $survey;
$logger->info("############# - End of Audit.pl - Execution time : " . $duration. " s ##############\n\n");




