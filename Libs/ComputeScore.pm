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

package ComputeScore;

use Exporter;
use Log::Log4perl;
use Data::Dumper;
@ISA = qw(Exporter);
@EXPORT = qw(compute_score compute_final_result);
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


sub compute_score {
	my @scores = @_;
	my $score;
	my @sorted_scores = sort { $a <=> $b } @scores;
	
	$score = ( ( $sorted_scores[0] + $sorted_scores[$#sorted_scores] ) / 2 );
	
	return $score;
}

sub compute_final_result {
	my ($audit) = @_;
	
	bless $audit, "Survey";
	my $res;
	my $grade;

	my $proto = ($audit->get_ssl)->{protocolScore};
	my $cipher = ($audit->get_ssl)->{cipherScore};

	my $content;
	if(defined($audit->get_content())){$content = ($audit->get_content)->{score};}
	#print $audit->get_hostName()."\n";	
	 
	if (!defined($audit->get_result())){ 
		$res =  proto_cipher_score($proto, $cipher);
		if(defined($audit->get_content())){
			$grade = letter_grade($res, ($audit->get_content())->{score});
		} else {
			$grade = letter_grade($res, 0);
		}

	}
	#print "Score : $res and grade : $grade \n";
	$audit->set_result($res);
	$audit->set_grade($grade);
	return $audit;
}

sub proto_cipher_score{
	my ($proto, $cipher) = @_;
	my $score;
	$logger->info(" - Info: Compute Protocol and Cipher final score");
	$score =(($proto * 0.3) + ($cipher * 0.7)); 

	return $score;
}
sub letter_grade {
	my ($score, $contentScore) = @_;
	my $grade;
	$logger->info(" - Info: Assigne the survey grade");
	if ( $score >= 80 ) {
		$grade = "A";
	} elsif ( $score >= 65 ) {
		$grade = "B";
	} elsif ( $score >= 50 ) {
		$grade = "C";
	} elsif ( $score >= 35 ) {
		$grade = "D";
	} elsif ( $score >= 20 ) {
		$grade = "E";
	} else {
		$grade = "F";
	}
	if($contentScore > 0){
		$grade .= "+";	
	} elsif ($contentScore < 0){
		$grade .= "-";
	}

	return ($grade);
}

1;
