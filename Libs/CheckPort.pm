=head1 NAME

check_port - Check port on server

=head1 SYNOPSIS

	if ( check_port( $host, $port ) ){
		# code
	}

=head1 DESCRIPTION

This Module check if the port on the server is open.

=head2 Arguments

=over

=item *

$host		# The host name

=item *

$port		# The host port for connection

=back

=head2 Return

=over

=item *

0 Connection refused to host $host on port $port

=item *

1 Connect to host=$host, port=$port - OK

=back

=head1 AUTHOR

Ameti Behar

=cut

package CheckPort;

use Socket;
use Log::Log4perl;
use Exporter;
# --- Import created classes used in the script
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Classes';
use Survey;

@ISA = qw(Exporter);
@EXPORT = qw(check_port);

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

sub check_port {
	my ( $audit ) = @_;
	my $host = $audit->get_hostName();
	my $port = $audit->get_port;
	print "$host : $port -";
	$logger->info(" - Checking port $port on host $host.");	
		
	if ( !$port or $port =~ /\D/ ) {
		$logger->warn(" - No or bad port define for host $host. Try with default port 443");		
		$port = "443";
		$audit->set_port("443");
	}

	my $iaddr = inet_aton($host) || $logger->fatal(" - No host: $host") && return 0;
	my $paddr = sockaddr_in( $port, $iaddr );
	my $proto = getprotobyname('tcp');
	
	socket( SOCK, PF_INET, SOCK_STREAM, $proto ) || $logger->fatal(" - Socket: $!") && return 0;
	if ( connect( SOCK, $paddr ) ) {
		$logger->info(" - Connect to host=$host:$port - OK");
		$logger->info(" - Close connection");
		close(SOCK) || $logger->fatal(" - Close $!") && die "close: $!";
		print " OK\n";
		return 1;
	} else {
		$logger->fatal(" - Connection refused to host $host on port $port");
		print " No OK\n";
		return 0;
	}
}
1;
