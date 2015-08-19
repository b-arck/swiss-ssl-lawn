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

my $output = "./Output/";
my $xmlfile = $output . get_file_name();

sub saveToxml {
	my ( @surveyTab ) = @_;
	
	# Create DOM XML object
	my $xmlDoc  = XML::LibXML::Document->new('1.0','UTF-8'); 
	my $root = $xmlDoc->createElement('SSL_Lawn');
	$xmlDoc->setDocumentElement($root);
	
	foreach my $survey (@surveyTab){
		bless $survey,"Survey";

		# Create SURVEY node with attribute
		my $element = $xmlDoc->createElement('SURVEY');
		$attr = $xmlDoc->createAttribute('ID',$survey->get_id);
		$element->setAttributeNode($attr);
		$attr = $xmlDoc->createAttribute('date',$survey->get_date);
		$element->setAttributeNode($attr);
		# Affect node element to root element
		$root->appendChild($element);

		# Create hostName node and affect to SURVEY element
		my $hostName = $xmlDoc->createElement('hostName');
		$hostName->appendChild($xmlDoc->createTextNode($survey->get_hostName));
		$element->appendChild($hostName);

		# Create ip node and affect to SURVEY element
		my $ip = $xmlDoc->createElement('ip');
		$ip->appendChild($xmlDoc->createTextNode($survey->get_ip()));
		$element->appendChild($ip);

		# Create result node and affect to SURVEY element
		my $result = $xmlDoc->createElement('result');
		$result->appendChild($xmlDoc->createTextNode($survey->get_result()));
		$element->appendChild($result);

		# Create result node and affect to SURVEY element
		my $grade = $xmlDoc->createElement('grade');
		$grade->appendChild($xmlDoc->createTextNode($survey->get_result()));
		$element->appendChild($grade);


		# Create result node and affect to SURVEY element
		my $ssl = $xmlDoc->createElement('ssl');
		$ssl->appendChild($xmlDoc->createTextNode($survey->get_result()));
		$element->appendChild($ssl);

		# For each SSL create a note and the cipher list		

	}
	

	# Affichage du XML sur la console
	#print $state = $xmlDoc->toString(0);
	# Sauvegarde de l'Objet XML dans un fichier.xml (dossier courant) le 1 permet la mise en page
	$state = $xmlDoc->toFile($xmlfile, 1);
	
}

sub get_file_name{
	
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
	my $nice_timestamp = sprintf ( "%04d%02d%02d_%02d%02d%02d", $year+1900,$mon+1,$mday,$hour,$min,$sec);
	my $filename = "Audite_" . $nice_timestamp ;
	return $filename;	
}

