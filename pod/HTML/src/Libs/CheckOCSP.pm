=head1 NAME

CheckOCSP - Check the certificate validity via OCSP request 

=head1 SYNOPSIS

C<use CheckProtocolCipher qw(check_protocol_cipher);>

C<my $ocsp = check_ocsp( $host, $port );>

=head1 DESCRIPTION

This module check the certificate validity via OCSP request.

=over

=item *

Create OCSP_REQUEST

=item *

Determine URI of OCSP responder

=item *

Send stringified OCSP_REQUEST with POST to

=item *

Extract OCSP_RESPONSE

=item *

Check status of response

=back

=head2 Arguments

=over

=item *

$host		# The host name

=item *

$port		# The host port

=back

=head2 Return

Returns a String with certificat status :

=over

=item *

return "OCSP certificate status is GOOD";

=item *

=item *

return "OCSP certificate status is REVOKED : " . $revocreason;

=item *
 
return "OCSP certificate status is UNKNOWN";

=back

=head1 AUTHOR

Ameti Behar 

=cut

package CheckOCSP;

use Log::Log4perl;
use Socket;
use Exporter;


@ISA = qw(Exporter);
@EXPORT = qw(check_ocsp);

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

sub check_ocsp {
	my ( $ssl, $x509 ) = @_;

	my $id = eval { Net::SSLeay::OCSP_cert2ids($ssl,$x509) };
	$logger->fatal(" - Failed to make OCSP_CERTID: $@"),die "Failed to make OCSP_CERTID: $@" if $@;

	$logger->info(" - Create OCSP_REQUEST from id(s)");
	my $req = Net::SSLeay::OCSP_ids2req($id);
	
	$logger->info(" - Determine URI of OCSP responder");
	my $uri = Net::SSLeay::P_X509_get_ocsp_uri($x509);
	$logger->info(" - Send stringified OCSP_REQUEST with POST to $uri.");
	my $ua = HTTP::Tiny->new(verify_SSL => 0);
	$res = $ua->request( 'POST',$uri, {
		headers => { 'Content-type' => 'application/ocsp-request' },
		content => Net::SSLeay::i2d_OCSP_REQUEST($req)
	});
	
	my $content = $res && $res->{success} && $res->{content} or $logger->fatal(" - Query failed") && die "Query failed";

	$logger->info(" - Extract OCSP_RESPONSE.");
	my $resp = eval { Net::SSLeay::d2i_OCSP_RESPONSE($content) };

	$logger->info(" - Check status of response.");
	my $status = Net::SSLeay::OCSP_response_status($resp);
	if ($status != Net::SSLeay::OCSP_RESPONSE_STATUS_SUCCESSFUL()){
		return "OCSP response failed: ".
		Net::SSLeay::OCSP_response_status_str($status);
	}
	 
	$logger->info(" - Extract information from OCSP_RESPONSE for each of the ids.");
	my @results = Net::SSLeay::OCSP_response_results($resp,my @ids);

	
	foreach my $r (@results) {
		if( $r->[2]{statusType} == 0){
			return "OCSP certificate status is GOOD";
		}
		elsif( $r->[2]{statusType} == 1){
			my $revocreason = $r->[2]{revocationReason_str};
			return "OCSP certificate status is REVOKED : " . $revocreason; 
		}
		else{
			return "OCSP certificate status is UNKNOWN";
		}
		# @results are in the same order as the @ids and contain:
		# $r->[0] - OCSP_CERTID
		# $r->[1] - undef if no error (certificate good) OR error message as string
		# $r->[2] - hash with details:
		#   thisUpdate - time_t of this single response
		#   nextUpdate - time_t when update is expected
		#   statusType - integer:
		#      V_OCSP_CERTSTATUS_GOOD(0)
		#      V_OCSP_CERTSTATUS_REVOKED(1)
		#      V_OCSP_CERTSTATUS_UNKNOWN(2)
		#   revocationTime - time_t (only if revoked)
		#   revocationReason - integer (only if revoked)
		#   revocationReason_str - reason as string (only if revoked)
	}
}
1;
