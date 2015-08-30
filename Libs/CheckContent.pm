=head1 NAME

CheckContent - Check basic web content and header 

=head1 SYNOPSIS

    check_content( $host, $port);

=head1 DESCRIPTION

This module check a lot of basic parameters on web content and header

=over 12

=item Server Type
=item Social network link
=item HSTS support
=item HTTPs redirect
=item Flash content in web page
=item Give an assessment

=back

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port 

=item Return

return $check;	# Hash ref with all check content datas

=back

=head1 AUTHOR

Ameti Behar 

=cut

package CheckContent;

use LWP::UserAgent;
use HTTP::Response;
use HTTP::Status qw(:constants :is status_message);
use Log::Log4perl;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(check_content);

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

sub check_content{
	my ($host) = @_;
	my $check = {};
	$logger->info(" - Cheking content");
	# Create a user agent object
	my $agent = LWP::UserAgent->new(env_proxy => 1,
					keep_alive => 1,
					timeout => 5, 
					ssl_opts => {
					verify_hostname => 0,
					SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,},);
	$agent->max_redirect(10);
	$agent->agent("Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:39.0) Gecko/20100101 Firefox/39.0");
	my $url = "http://$host"; 
	
	$logger->info(" - Cheking HTTP Header for server type and HTTPs redirect on HTTP request");
	
	my $response = $agent->get($url);
	my $request = $response->request();
	my @redirects = $response->redirects();
	
	$count = @redirects;
	$check->{srv_type}=undef;
	$check->{flash_content}=undef;
	$scheck->{score}=undef;
	$scheck->{status_code}=undef;
	
	my $i =0 ;
	if ($response->is_success) {
		# if there is no redirect check flash and server type in the response		
		if($count == 0){
			$logger->info(" - Retrieve Server Type information");
			$check->{srv_type}=$response->header("Server");
			$check->{flash_content} = check_flash_Content($response);
		}
		$scheck->{status_code} = $response->status_line;
		foreach my $res (@redirects) {	
			my $req = $res->request();
						
			if($res->header("Server")){$check->{srv_type}=$res->header("Server");}
		
			if ($i == $count-1 && $res->header("Location") =~ m/https/){

				$logger->info(" - Check if Strict-Transport-Security is implemented");
				if($res->header("Strict-Transport-Security")){
				
					$check->{https_redirect} = "Yes";
					$check->{hsts} = "Yes";
					$check->{score} += 2;
				}else{
					$check->{https_redirect} = "Yes";
					$check->{hsts} = "No";
					$check->{score} += 0;
				}
			} else {
				$check->{https_redirect} = "No";
				$check->{hsts} = "No";
				$check->{score} -= 1;
			}
			$i++;
			$check->{flash_content} = check_flash_Content($res);
		}
		if(!($check->{ext_content} = check_ext_content($response)) ){
			$check->{score} += 1;
		} else {
			$check->{score} -= 1;
		}
		if($scheck->{flash_content} == 0){
			$check->{score} += 1;	
		} else {
			$check->{score} -= 1;
		}
		return $check;
	}
	 else {
		$logger->fatal(" - Fatal: Http response code " . $response->status_line);
		$scheck->{status_code} = $response->status_line;		
		return $check;
	}
}

sub check_ext_content{
	my ($response) = @_;
	$logger->info(" - Check if there are social link");
	my @extCont;
	if ($response->decoded_content =~ m/facebook.com/){push @extCont, "FB";} # or whatever
	if ($response->decoded_content =~ m/plus.google.com/){push @extCont, "GP";}
	if ($response->decoded_content =~ m/twitter.com/){push @extCont, "TW";}
	if ($response->decoded_content =~ m/linkedin.com/){push @extCont, "Ln";}
	if ($response->decoded_content =~ m/google-analytics/){push @extCont, "GA";}
	
	return \@extCont;
}

sub check_flash_Content{
	my ($response) = @_;
	$logger->info(" - Check if there are flash content");
	if($response->header("Content-Type") =~ m/x-shockwave-flash/ or 
		$response->header("Content-Type") =~ m/video\/x-flv/){
		return 1;
	}
	return 0;
}


