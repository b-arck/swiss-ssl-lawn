#!/usr/bin/env perl

use warnings;
use strict;

use Socket;
use Net::SSLeay qw(die_now die_if_ssl_error);

use IO::Socket::SSL qw(debug0);

use Time::gmtime;
use Time::ParseDate;
use HTTP::Tiny;
use Data::Dumper;
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
Net::SSLeay::randomize();

my ($dest_serv, $port) = ("www.migros.ch","443");    # Read command line
$port = getservbyname( $port, 'tcp' ) unless $port =~ /^\d+$/;
	my $dest_ip = gethostbyname($dest_serv);
	my $dest_serv_params = sockaddr_in( $port, $dest_ip );

	socket( S, &AF_INET, &SOCK_STREAM, 0 ) or die "socket: $!";
	connect( S, $dest_serv_params ) or die "connect: $!";
	select(S);
	$| = 1;
	select(STDOUT);                   # Eliminate STDIO buffering

	# The network connection is now open, lets fire up SSL

	my $ctx = Net::SSLeay::CTX_new() or die_now("Failed to create SSL_CTX $!");
	Net::SSLeay::CTX_set_options( $ctx, &Net::SSLeay::OP_ALL )
	  and die_if_ssl_error("ssl ctx set options");
	my $ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
	Net::SSLeay::set_fd( $ssl, fileno(S) );    # Must use fileno
	my $res = Net::SSLeay::connect($ssl) and die_if_ssl_error("ssl connect");

# get id(s) for given certs, like from get_peer_certificate
# or get_peer_cert_chain. This will croak if
# - one tries to make an OCSP_CERTID for a self-signed certificate
# - the issuer of the certificate cannot be found in the SSL objects
#   store, nor in the current certificate chain
my $cert = Net::SSLeay::get_peer_certificate($ssl);

my $id = eval { Net::SSLeay::OCSP_cert2ids($ssl,$cert) };
die "failed to make OCSP_CERTID: $@" if $@;

# create OCSP_REQUEST from id(s)
# Multiple can be put into the same request, if the same OCSP responder
# is responsible for them.
my $req = Net::SSLeay::OCSP_ids2req($id);
 
# determine URI of OCSP responder
my $uri = Net::SSLeay::P_X509_get_ocsp_uri($cert);
# Send stringified OCSP_REQUEST with POST to $uri.
# We can ignore certificate verification for https, because the OCSP
# response itself is signed.
my $ua = HTTP::Tiny->new(verify_SSL => 0);
$res = $ua->request( 'POST',$uri, {
    headers => { 'Content-type' => 'application/ocsp-request' },
    content => Net::SSLeay::i2d_OCSP_REQUEST($req)
});

my $content = $res && $res->{success} && $res->{content}
    or die "query failed";

# Extract OCSP_RESPONSE.
# this will croak if the string is not an OCSP_RESPONSE
my $resp = eval { Net::SSLeay::d2i_OCSP_RESPONSE($content) };

# Check status of response.
my $status = Net::SSLeay::OCSP_response_status($resp);
if ($status != Net::SSLeay::OCSP_RESPONSE_STATUS_SUCCESSFUL()){
    die "OCSP response failed: ".
        Net::SSLeay::OCSP_response_status_str($status);
}
 
# Extract information from OCSP_RESPONSE for each of the ids.
 
# If called in scalar context it will return the time (as time_t), when the
# next update is due (minimum of all successful responses inside $resp). It
# will croak on the following problems:
# - response is expired or not yet valid
# - no response for given OCSP_CERTID
# - certificate status is not good (e.g. revoked or unknown)
if ( my $nextupd = eval { Net::SSLeay::OCSP_response_results( $resp, $id) }) {
    warn "certificate is valid, next update in ".
        ($nextupd-time())." seconds\n";
} else {
    die "certificate is not valid: $@";
}
 
# But in array context it will return detailled information about each given
# OCSP_CERTID instead croaking on errors:
# if no @ids are given it will return information about all single responses
# in the OCSP_RESPONSE
my @results = Net::SSLeay::OCSP_response_results($resp,my @ids);

foreach my $r (@results) {
    print Dumper($r)."hello";
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
