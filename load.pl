#!/usr/bin/perl
use XML::Dumper;
# --- Import created classes used in the script
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Classes';
use Survey;
use Log::Log4perl;
use Data::Dumper;
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

	print dirname(dirname abs_path $0);
	my ( @surveyTab ) = @_;

	$dump = new XML::Dumper;
	my $perl = $dump->xml2pl("/home/beharameti/Desktop/Script/Output/Audite_21082015_000037.xml" );
	
	
	print Dumper($perl);
