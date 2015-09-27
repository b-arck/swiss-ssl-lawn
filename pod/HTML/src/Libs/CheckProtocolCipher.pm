=pod

=head1 NAME

CheckProtocolCipher - Check the SSL version supported and the cipher implemented by the server

=head1 SYNOPSIS

C<check_protocol_cipher( $host, $port, $iniFile);>

=head1 DESCRIPTION

This module check the SSL version supported by the server and
for each protocol, it check a list of chipher (.ini file). Each protocol is tested by a thread.

=head2 Arguments

=over

=item *

$host		# The host name

=item *

$port		# The host port

=item *

$iniFile	# File with Protocol and cipher to test

=back

=head2 Return

=over

=item *

return $checkProtoCihperList	# Hash ref with all tests

=back

=head1 AUTHOR

Ameti Behar 

=cut

package CheckProtocolCipher;

use IO::Socket::SSL;
use Socket;
use Log::Log4perl;
use Config::IniFiles;
use Data::Dumper;
use threads;
use threads::shared;
use Exporter;
use ComputeScore qw(compute_score compute_final_result );

@ISA = qw(Exporter);
@EXPORT = qw(check_protocol_cipher);

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

sub check_protocol_cipher {
	my ( $host, $port, $file ) = @_;

	$logger->info(" - Loading ini file");
	my $cfg = new Config::IniFiles( -file => $file ) or $logger->fatal(" - Fatal: Can't read $file") 
							&& die( "Can't read $file" . $@ );
	my @protocols = $cfg->Sections;

	my $protocol;
	my $cipher;
	my $checkProtoCihperList = {};
	my @protocol_scores = ();
	my @cipher_scores   = ();
	my (@threads);
my $current :shared;
$current = 0;
	$logger->info(" - Checking protocol and cipher support for host : $host");
	#print "host : $host\n";
	foreach $protocol (@protocols) {
		my @ciphers = $cfg->Parameters($protocol);
		# Launch check with threads foreach Protocol
		my $thr = threads->new(\&check, \@ciphers, $protocol, $cfg, $host, $port,$_);
		push(@threads,$thr);
	
	}# foreach $protocol (@protocols)
	foreach (@threads) {
		my $thr = $_->join();
		$key = (keys $thr)[0];
		$checkProtoCihperList->{protocol}->{$key} = $thr->{$key};
		
		if($checkProtoCihperList->{protocol}->{$key}->{implemented} eq "yes" or $checkProtoCihperList->{protocol}->{$key} eq "TLSv12"){
			push @protocol_scores, $checkProtoCihperList->{protocol}->{$key}->{protocolScore};
			push @cipher_scores, $checkProtoCihperList->{protocol}->{$key}->{cipherScore} . "\n";
		}
	}
	
	$logger->info(" - Info: Compute " . $host . " protocol and cipher result");
	$checkProtoCihperList->{protocolScore} = compute_score(@protocol_scores);
	$checkProtoCihperList->{cipherScore} = compute_score(@cipher_scores);
	return $checkProtoCihperList;
}

sub check_connect {
	my ( $host, $port, $ssl_version, $cipher ) = @_;
	my %server_options = (
		SSL_version     => $ssl_version,
		SSL_cipher_list => $cipher,
		PeerAddr        => $host,
		PeerPort        => $port
	);
	
	if ( my $client = IO::Socket::SSL->new(%server_options) ) {
		close $client;
		return 1;    # Connection accepted
	} else {
		close $client;
		return 0;    # Connection failed
	}
	
}

sub check{
	my ( $ciphersR, $protocol, $cfg, $host, $port, $thr ) = @_;
	my $checkProtoCihperList = {};
	my @ciphers = @$ciphersR;
	
	my @protocol_scores;
	my @cipher_scores;

	# Used for cipher indexing in hashe table
	my $i = 0;
	my $j = 0;

	foreach $cipher (@ciphers) {
		my $success = check_connect( $host, $port, $protocol, $cipher );
		my $score = $cfg->val( $protocol, $cipher );
		
		# Remove comments and whitespace before comments
		$score =~ s/\s*[\#\;].*//g;
		# $protocol - $cipher - tested successfull
		if ($success) {
			# The "DEFAULT" cipher is being tested. the protocol itself
			if ( $cipher =~ m/DEFAULT/i ) {
				
				$checkProtoCihperList->{protocol}->{$protocol}->{protocolScore} = $score;
				$checkProtoCihperList->{protocol}->{$protocol}->{implemented} = "yes";
			} else {
				
				if ($score < 60){
					$checkProtoCihperList->{protocol}->{$protocol}->{AcceptedCipher}->[$i] = $cipher;
				} else{				
					# A cipher is being tested
					$checkProtoCihperList->{protocol}->{$protocol}->{AcceptedCipher}->[$i] = $cipher;
				}
				push @$cipher_scores, $score;
				$i++;
			}
		} else {
			# The "DEFAULT" cipher is being tested. the protocol is not implemented
			if ( $cipher =~ m/DEFAULT/i ) {
				
				$checkProtoCihperList->{protocol}->{$protocol}->{protocolScore} = 0;
				$checkProtoCihperList->{protocol}->{$protocol}->{implemented} = "no";
				$checkProtoCihperList->{protocol}->{$protocol}->{cipherScore} = 0;
				last;
			} 
		}
		
	} # foreach $cipher (@ciphers)
	
	if ( @$cipher_scores > 0 ) {
		# Compute cipher liste score 
		$checkProtoCihperList->{protocol}->{$protocol}->{cipherScore} = compute_score(@$cipher_scores);
	} else {
		# Attribute zero if no cipher in list
		$checkProtoCihperList->{protocol}->{$protocol}->{cipherScore} = "0";
	}
	return $checkProtoCihperList->{protocol};

}

1;
