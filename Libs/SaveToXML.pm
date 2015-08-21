=head1 NAME

GetCertDetails - Module to get certificate details 

=head1 SYNOPSIS

	use GetCertDetails qw(check_protocol_cipher);

	$cert_details = get_cert_details( $host, $port );

=head1 DESCRIPTION

This module get the host certificate and extract all informations.

=over 12

=item subject
=item issuer
=item alternative names
=item hashes/fingerprints
=item expiration date
=item serial number
=item version
=item extensions (oid, nid, ln, sn, data)
=item crl_distribution_points
=item extended key usage
=item netscape cert type\n";
=item certificate, signature and public key info\n";
=item certificate in .pem format

=back

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port for connection

=item Return

A COMPLETER

=back

=head1 AUTHOR

Ameti Behar 

=cut

package SaveToXML;

use Time::gmtime;
use Time::ParseDate;
use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(saveToxml);

# --- Import created module used in the script

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Libs';
use Log::Log4perl;
use XML::Dumper;
use Data::Dumper;
# --- Import created classes used in the script
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Classes';
use Survey;

# Initialize Logger
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

my $xmlfile = get_file_name();


sub saveToxml{
	my ( @surveyTab ) = @_;

	$dump = new XML::Dumper;

	$xml  = $dump->pl2xml( @surveyTab );
	$perl = $dump->xml2pl( $xml );
	$dump->pl2xml( $perl, dirname(dirname abs_path $0) . '/Script/Output/' . $xmlfile );
    
}

sub get_file_name{
	
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
	my $nice_timestamp = sprintf ( "%02d%02d%04d_%02d%02d%02d", $mday,$mon+1,$year+1900,$hour,$min,$sec);
	my $filename = "Audite_$nice_timestamp.xml" ;
	return $filename;	
}


