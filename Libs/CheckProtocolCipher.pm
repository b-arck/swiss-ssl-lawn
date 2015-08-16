=pod

=head1 NAME

CheckProtocolCipher - Module to check the SSL version supported and the cipher implemented by the server

=head1 SYNOPSIS

	use CheckProtocolCipher qw(check_protocol_cipher);

	my $success = check_protocol_cipher( $host, $port, $protocol, $cipher );

=head1 DESCRIPTION

This module check the SSL version supported by the server and
for each version it check a list of chipher.

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port for connection
$protocol	# Protocol to be checked
$cipher		# Cipher to be checked

=item Return

Returns a boolean (1 or 0)

=back

=head1 AUTHOR

Ameti Behar 

=cut

package CheckProtocolCipher;

use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(check_protocol_cipher);

use IO::Socket::SSL;
use Socket;
use Config::IniFiles;
use Data::Dumper;

# --- Import created classes used in the script

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Classes';
use Survey;


# --- Logging info message for debug
use Log::Log4perl;
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

sub check_protocol_cipher {
	my ( $host, $port, $file ) = @_;

	my $cfg = new Config::IniFiles( -file => $file ) or $logger->fatal(" - Fatal: Can't read $file") && die( "Can't read $file" . $@ );
	my @protocols = $cfg->Sections;

	my $protocol;
	my $cipher;
	my $checkProtoCihperList ={};
	my $i;
	my $j;
	my @protocol_scores = ();
	my @cipher_scores   = ();

	$logger->info(" - Info: checking protocol and cipher support");
	foreach $protocol (@protocols) {
		my @ciphers = $cfg->Parameters($protocol);
		$checkProtoCihperList->{protocol}->{$protocol};
		$i = 0;
		$j = 0;
		foreach $cipher (@ciphers) {
			my $success = check( $host, $port, $protocol, $cipher );
			my ( $score );

			if ($success) {
				$score = $cfg->val( $protocol, $cipher );
				# Remove comments and whitespace before comments
				$score =~ s/\s*[\#\;].*//g;

				if ( $cipher =~ m/DEFAULT/i ) {
					# The "DEFAULT" cipher is being tested, i.e. the protocol itself
					push @protocol_scores, $score;
					$checkProtoCihperList->{protocol}->{$protocol}->{Score} = $score;
					$checkProtoCihperList->{protocol}->{$protocol}->{implemented} = "yes";
				} else {
					# A particular cipher is being tested
					$checkProtoCihperList->{protocol}->{$protocol}->{AcceptedCipher}->[$i] = {cipher => $cipher,};
					push @cipher_scores, $score;
					$i++;
				}
				#print "$protocol - $cipher - successfull - $score\n";

			} else {
				if ( $cipher =~ m/DEFAULT/i ) {
					$checkProtoCihperList->{protocol}->{$protocol}->{implemented} = "no";
					
				} else {
					$checkProtoCihperList->{protocol}->{$protocol}->{RejectedCipher}->[$j] = {cipher => $cipher,};
					$j++;
				}
			}
		} # foreach $cipher (@ciphers)
		
		if ( @cipher_scores > 0 ) {
			# We got some cipher scores 
			$checkProtoCihperList->{protocol}->{$protocol}->{cipherScore} = compute_score(@cipher_scores);;
			@cipher_scores = ();
		} else {
			$checkProtoCihperList->{protocol}->{$protocol}->{score} = "0";
			#print "$protocol not supported by server\n";
		}
	}# foreach $protocol (@protocols)
	$logger->info(" - Info: Compute " . $host . " protocol and cipher result");
	$checkProtoCihperList->{protocol}->{protocolScore} = compute_score(@protocol_scores);
	return $checkProtoCihperList;
}

sub check {
	my ( $host, $port, $ssl_version, $cipher ) = @_;
	
	my %server_options = (
		SSL_version     => $ssl_version,
		SSL_cipher_list => $cipher,
		PeerAddr        => $host,
		PeerPort        => $port
	);
	
	if ( my $client = IO::Socket::SSL->new(%server_options) ) {
		return 1;    # Connection accepted
	} else {
		return 0;    # Connection failed
	}
	close($client);
}

sub letter_grade {
	my $score = shift(@_);
	my $grade;

	if ( $score >= 80 ) {
		$grade = "A";
	} elsif ( $score >= 60 ) {
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

	return ($grade);
}

sub compute_score {
	my @scores = @_;
	my $score;
	my @sorted_scores = sort { $a <=> $b } @scores;
	
	$score = ( ( $sorted_scores[0] + $sorted_scores[$#sorted_scores] ) / 2 );
	
	return ( $score);
}
1;
