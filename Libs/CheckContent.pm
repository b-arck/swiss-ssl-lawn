=head1 NAME

CheckOCSP - Module to check the certificate validity via OCSP request 

=head1 SYNOPSIS

    use CheckProtocolCipher qw(check_protocol_cipher);

    my $ocsp = check_ocsp( $host, $port );

=head1 DESCRIPTION

This module check the certificate validity via OCSP request.
the steps to do this check are : 

=over 12

=item create OCSP_REQUEST
=item determine URI of OCSP responder
=item Send stringified OCSP_REQUEST with POST to
=item Extract OCSP_RESPONSE
=item Check status of response

=back

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port for connection

=item Return

Returns a String with certificat status. There are 3 status to return.

return "OCSP certificate status is GOOD";
return "OCSP certificate status is REVOKED : " . $revocreason; 
return "OCSP certificate status is UNKNOWN";

=back

=head1 AUTHOR

Ameti Behar 

=cut

package CheckContent;

use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(check_content);

use LWP::UserAgent;
use HTTP::Response;
use HTTP::Status qw(:constants :is status_message);
use Log::Log4perl;

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

sub check_content{
	my ($host) = @_;

	$logger->info(" - Info: Cheking content");
	# Create a user agent object
	my $agent = LWP::UserAgent->new(env_proxy => 1,keep_alive => 1, timeout => 30); 
	$agent->agent("Mozilla/5.0 (Windows NT 6.1)");
	my $url = "http://$host/"; 
	
	check_redirect($agent, $url);

	
}

=pod
	my $header = HTTP::Request->new(GET => $url); 
	my $request = HTTP::Request->new('GET', $url, $header); 
	my $response = $agent->request($request);
	print $url;
	
	check_redirect($agent, $request);
	#print $response;
	#print $response->status_line;
	# Check the outcome of the response
	if ($response->is_success) {
		#print $response->content;
		
		print $response->header( "Server" );
		print $response->header( "Content-Type" );
		print $response->header( "Status-Code" );
		print "\n";

	}
	else {
		#print $response->status_line, "\n";
		$logger->warn(" - Warn: HTTP Response not successful");		
	}
}
=cut
sub check_redirect{
	my ($agent, $url) = @_;
	$agent->max_redirect(5);
	$logger->info(" - Info: Check if HTTPs redirect on HTTP request");
	
	my $response = $agent->get($url);
	my $request = $response->request();
	my @redirects = $response->redirects();
	
	my $i =0 ;
	foreach my $res (@redirects) {
		my $req = $res->request();
		#print $res->header_field_names;
		print $res->header("Location") . " $i\n";
		#print($req->as_string());
		#print($res->as_string());
		if($res->header("Strict-Transport-Security")){
			#print $res->header("Strict-Transport-Security");
			print "HSTS\n";		
		}
		else{
			print "No HSTS\n";		
		}
		if ($res->header("Location") =~ m/https/){print "HTTPS redirect OK";}
		$i++;
	}
	
	#print($request->as_string());
	#print($response->as_string());
}

