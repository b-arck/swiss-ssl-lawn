#!/usr/bin/perl

=head1 SSL – Swiss SSL Lawn

=head2 DESCRIPTION

This script allows to audit SSL security settings of web servers



=head2 AUTEUR

Ameti Behar

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

# --- Import created module used in the script

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Libs';
use CheckProtocolCipher qw(check_protocol_cipher);
use CheckOCSP qw(check_ocsp);
use GetCertDetails qw(get_cert_details);
use CheckContent qw(check_content);
use SaveToXML qw(saveToxml);
# --- Import created classes used in the script
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Classes';
use Survey;

# --- Logging info message for debug


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

# --- Fonctions used in the script

sub check_init{
	my ( $xmlListe, $protoCipherFile, @moduleList ) = @_;

	$logger->info(" - Info: checking Script init.");
	if(!-d "BDD",){die "Folder BDD don't exist. Can't continue\n";}
	if(!-d "ini",){die "Folder ini don't exist. Can't contine\n";}
	if(!-d "Output"){
		$logger->warn(" - Info: Folder Output don't exist. Creating foler");
		mkdir "Output";
	}
	if (-d "Libs") {
    		if (is_folder_empty("Libs")) {die "Folder Libs contain no module. Can't continue\n";}
	}
	else{
		die "Folder Libs don't exist. Can't continue\n";
	}
	if(!-f $xmlListe, ){ die "Hosts list don't exist. Can't contiue the script\n";}
	if(!-f $protoCipherFile, ){ die "Protocol and Cipher list don't exist. Can't contiue the script\n";}
	
	foreach my $module (@moduleList){		
		if (!try_load_module($module)) {die "Missing module : " . $module ."\n";}
	}

	$logger->info(" - Info: checking XML hosts file.");
	# XML file parsing to retrieve hosts informations
	my $parser = XML::LibXML->new;
	my $dom = $parser->parse_file($xmlListe);
	my @hosts = $dom->getElementsByTagName("host");
	if(!@hosts){die "file " . $xmlListe . " existe but is empty" ;}
	
	return @hosts;
}

sub is_folder_empty {
    my $dirname = shift;
    opendir(my $dh, $dirname) or die "Not a directory";
    return scalar(grep { $_ ne "." && $_ ne ".." } readdir($dh)) == 0;
}

sub try_load_module {
	my $mod = shift;

	eval("use $mod");

	if ($@) {
		return(0);
	} else {
		return(1);
	}
}

=head1 NAME

check_port - Check port on server

=head1 SYNOPSIS

	if ( check_port( $host, $port ) ){
		# code
	}

=head1 DESCRIPTION

This subroutine check if the port on the server is open.

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port for connection

=item Return

boolean (0 or 1)

=back

=head1 AUTHOR

Ameti Behar 

=cut

sub check_port {
	my ( $host, $port ) = @_;

	$logger->info(" - Info: checking port $port on host $host.");	
	# if no or bad information port define, use port 443 by default	
	if ( !$port or $port =~ /\D/ ) {
		$logger->warn(" - Warn: No or bad port define for host $host. Try with default port 443");		
		$port = "443";
	}

	my $iaddr = inet_aton($host) || $logger->fatal(" - Fatal: no host: $host") && die "no host: $host";
	my $paddr = sockaddr_in( $port, $iaddr );
	my $proto = getprotobyname('tcp');
	
	socket( SOCK, PF_INET, SOCK_STREAM, $proto ) || $logger->fatal(" - Fatal: socket: $!") && die "socket: $!";
	if ( connect( SOCK, $paddr ) ) {
		$logger->info(" - Info: #### connect to host=$host, port=$port - OK");
		$logger->info(" - Info: Close connection");
		close(SOCK) || $logger->fatal(" - Fatal: close $!") && die "close: $!";
		return 1;
	} else {
		$logger->fatal(" - Info: Connection refused to host $host on port $port");
		return 0;
	}
}


=head1 NAME

check_hostname - Check the host name

=head1 SYNOPSIS

	if ( check_hostname( $host, $port ) ){
		# code
	}

=head1 DESCRIPTION

This subroutine check if the host name is the same in certificate.

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port for connection

=item Return

boolean (0 or 1)

=back

=head1 AUTHOR

Ameti Behar 

=cut

sub check_hostname {
	# Verify hostname / CN Name
	my ( $host, $port ) = @_;

	$logger->info(" - Info: checking hostname $host");

	my %server_options = (
		PeerAddr => $host,
		PeerPort => $port,
		SSL_ca_file => Mozilla::CA::SSL_ca_file(),
		#SSL_ca_path => '/etc/ssl/certs', # typical CA path on Linux
		SSL_verifycn_name => $host,
        	SSL_verifycn_scheme => 'http',
		SSL_hostname => $host
	);

	if ( my $client = IO::Socket::SSL->new(%server_options) ) {
		if ( !$client->verify_hostname( $host, 'http' ) ) {
			$logger->info(" - Info: Hostname verification failed");
			return 0;
		} else {
			if($client->peer_certificate('commonName')){
				$logger->info(" - Info: Certificate CN: " 
						. $client->peer_certificate('commonName') . " == Hostname: $host");
			} else {
				$logger->info(" - Info: CommonName is not part of certificat for Hostname: $host");
			}
			return 1;
		}
	} else {
		$logger->fatal(" - Info: Connection refused to host $host on port $port");
		return 0;
	}
}

# --- "Module" used in the script

sub get_time {

    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
    my $nice_timestamp = sprintf ( "%02d.%02d.%04d %02d:%02d:%02d",$mday,$mon+1,$year+1900,$hour,$min,$sec);
    return $nice_timestamp;
}

# --- Script varaibles

my $xmlListe = "BDD/hostsList.xml";
my $protoCipherFile = "ini/ProtoCipher.ini";
my @moduleList =("HTTP::Tiny","Getopt::Long","XML::LibXML","XML::Dumper","XML::Simple",
		"Data::Dumper","IO::Socket::SSL","Socket","Net::SSLeay","Config::IniFiles",
		"Time::gmtime","Time::ParseDate","Log::Log4perl","LWP::UserAgent","HTTP::Response");
my $host;
my $port;
my $hostType="";
my $hostID;
my $surveyH = {};

my @survey = ();

my $start = time;
$logger->info("############## - Info: Start Audit.pl the " . get_time() . " - ##############");

# --- Script test init

my @hosts = check_init($xmlListe, $protoCipherFile, @moduleList);
my $i = 0;
# --- Main script
foreach my $host (@hosts) {
	
	# Get port number
	$port = $host->getAttribute("port");
	$hostType = $host->getAttribute("type");
	$hostID = $host->getAttribute("ID");
	
	# Get host name
	$host = $host->firstChild->data;
	
	my $audit = Survey->new();
	$audit->set_hostName($host);
	$audit->set_date(get_time());
	$audit->set_id($hostID);
	$audit->set_hostType($hostType);

	if ( check_port( $host, $port ) ) {
		if ( check_hostname( $host, $port ) ) {

			# Check protocol and cipher
			$audit->set_ssl(check_protocol_cipher( $host, $port, $protoCipherFile ));
			# Get cert details			
			my ( $pem, $cert_details  ) = get_cert_details( $host, $port );
			$audit->set_pemcert($pem);
			$audit->set_cert($cert_details);
			$audit->set_ip(inet_ntoa(inet_aton($host)));
			$audit->set_content(check_content($host));
			
		}# if !check_hostname
		else{
			# If host name don't match give F result
			$audit->set_result("F");
		}
	}# if check_port
	$logger->info("----------------------------------------------------------");
	$surveyH->{$i} = $audit;
	$i++;

}# foreach host
my $duration = time - $start;

saveToxml($surveyH);
$logger->info("############# - Info: End of Audit.pl - Execution time : " . $duration. " s ##############\n\n");




