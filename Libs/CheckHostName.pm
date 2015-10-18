=head1 NAME

check_hostname - Check the host name

=head1 SYNOPSIS

C<if ( check_hostname( $host, $port ) ){>
		C<# code>
	C<}>

=head1 DESCRIPTION

This Module check the following information with IO::Socket::SSL

=over

=item *

Mozilla CA file (trusted or not)

=item *

Host name missmatch

=back

=head2 Arguments

=over

=item *

$host		# The host name

=item *

$port		# The host port 

=back

=head2 Return

=over

=item *

0 if Hostname verification failed or Connection refused

=item *

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
	my ( $audit ) = @_;

	my $host = $audit->get_hostName();
	my $port = $audit->get_port();

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
				$logger->info(" - Certificate CN: ". $client->peer_certificate('commonName') . " == Hostname: $host");
				
			} else {
				$logger->info(" - CommonName is not part of certificat for Hostname: $host");
			}
			return 1;
		}
	} else {
		
		if( check_SNI($host) eq 0){
			return 1;
		}else{
			$logger->fatal(" - Connection refused to host $host on port $port");
			return 0;
		}
	}
}

sub check_SNI{
	my ( $host ) = @_;
	Net::SSLeay::initialize();
	my $sock = IO::Socket::INET->new(PeerAddr=>"$host:443") or die;

	my $ctx = Net::SSLeay::CTX_tlsv1_new() or die;
	my $ssl = Net::SSLeay::new($ctx) or die;
	Net::SSLeay::set_tlsext_host_name($ssl, $host);
	Net::SSLeay::set_fd($ssl, fileno($sock)) or die;
	Net::SSLeay::CTX_set_verify($ctx, 0x02);
	Net::SSLeay::CTX_load_verify_locations($ctx, '/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/certs/');
	my $res = Net::SSLeay::connect($ssl);

	my ($resp, $server_cert, $verify, $key_size, $cipher_bits);
	my ($issuer, $subject, $not_before, $not_after, @altnames, $key_alg, $sign_alg, $match_cn, $match_root);
	if ($res) {
		$res = Net::SSLeay::do_handshake($ssl);
		if ($res) {
			$verify = Net::SSLeay::get_verify_result($ssl);
		}
	}
	Net::SSLeay::clear($ssl);
	Net::SSLeay::free($ssl);	
	return $verify;
}
1;
