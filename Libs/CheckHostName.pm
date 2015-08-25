=head1 NAME

check_hostname - Check the host name

=head1 SYNOPSIS

	if ( check_hostname( $host, $port ) ){
		# code
	}

=head1 DESCRIPTION

This Module check the following information with IO::Socket::SSL

=over 12
=item Mozilla CA file (trusted or not)
=item Host name missmatch

=back

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port 

=item Return

0 if Hostname verification failed or Connection refused
1 if Hostname is valid and Cert is trusted

=back

=head1 AUTHOR

Ameti Behar 

=cut

package CheckHostName;

use Log::Log4perl;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(check_hostname);

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

sub check_hostname {
	# Verify hostname / CN Name
	my ( $hostR, $portR ) = @_;

	my $host = $$hostR;
	my $port = $$portR;

	$logger->info(" - Checking hostname $host");

	my %server_options = (
		PeerAddr => $host,
		PeerPort => $port,
		SSL_ca_file => Mozilla::CA::SSL_ca_file(),
		SSL_verifycn_name => $host,
        	SSL_verifycn_scheme => 'http',
		SSL_hostname => $host
	);

	if ( my $client = IO::Socket::SSL->new(%server_options) ) {
		if ( !$client->verify_hostname( $host, 'http' ) ) {
			$logger->info(" - Hostname verification failed");
			
			return 0;
		} else {
			if($client->peer_certificate('commonName')){
				$logger->info(" - Certificate CN: " 
						. $client->peer_certificate('commonName') . " == Hostname: $host");
				
			} else {
				$logger->info(" - CommonName is not part of certificat for Hostname: $host");
			}
			return 1;
		}
	} else {
		$logger->fatal(" - Connection refused to host $host on port $port");
		
		return 0;
	}
}
1;
