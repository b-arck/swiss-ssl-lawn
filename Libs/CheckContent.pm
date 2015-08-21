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
use Data::Dumper;

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
	my $check = {};
	$logger->info(" - Info: Cheking content");
	# Create a user agent object
	my $agent = LWP::UserAgent->new(env_proxy => 1,keep_alive => 1, timeout => 50, ssl_opts => {
							verify_hostname => 0,
							SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,
							},);
 
	$agent->max_redirect(5);
	$agent->agent("Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:39.0) Gecko/20100101 Firefox/39.0");
	my $url = "http://$host"; 
	
	$logger->info(" - Info: Cheking HTTP Header for server type and HTTPs redirect on HTTP request");
	
	my $response = $agent->get($url);
	my $request = $response->request();
	my @redirects = $response->redirects();
	$count = @redirects;
	$check->{srv_type}=undef;
	my $i =0 ;
	print $response->as_string();
	if ($response->is_success) {
		foreach my $res (@redirects) {	
			my $req = $res->request();
			#print $res->header("Server");print "\n";
			#print $res->status_line();
			if($res->header("Server")){$check->{srv_type}=$res->header("Server");}
		
			if ($i == $count-1 && $res->header("Location") =~ m/https/){

				$logger->info(" - Info: Check if Strict-Transport-Security is implemented");
				if($res->header("Strict-Transport-Security")){
				
					$check->{https_redirect} = "Yes";
					$check->{hsts} = "Yes";		
				}else{
					$check->{https_redirect} = "Yes";
					$check->{hsts} = "No";		
				}
			} elsif($i == $count-1 && $res->header("Location") =~ m/http/){
				$check->{https_redirect} = "No";
				$check->{hsts} = "No";
			}
			$i++;
		}
		$check->{ext_content} = check_ext_content($response);
		return $check;
	}
	 else {
		$logger->fatal(" - Fatal: Http response code " . $response->status_line);
		return $check = undef;
	}
}

sub check_ext_content{
	my ($response) = @_;
	
	my @extCont;
	if ($response->decoded_content =~ m/facebook.com/){push @extCont, "FB";} # or whatever
	if ($response->decoded_content =~ m/plus.google.com/){push @extCont, "GP";}
	if ($response->decoded_content =~ m/twitter.com/){push @extCont, "TW";}
	if ($response->decoded_content =~ m/linkedin.com/){push @extCont, "Ln";}
	if ($response->decoded_content =~ m/google-analytics/){push @extCont, "GA";}
	
	return \@extCont;
}
