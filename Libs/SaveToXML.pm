=head1 NAME

SaveToCML - Module that dump the object to an XML file 

=head1 SYNOPSIS

C<saveToxml($survey);>

=head1 DESCRIPTION

This module can dump an object to an XML file

=head1 AUTHOR

Ameti Behar 

=cut

package SaveToXML;

use Time::gmtime;
use Time::ParseDate;
use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(saveToxml);

# --- Import created module used in the script

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Libs';
use Log::Log4perl;
use XML::Dumper;
use Data::Dumper;
# --- Import created classes used in the script
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Classes';
use Survey;

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


sub saveToxml{
	my ($surveyH,$folderName,$xmlfile) = @_;

	$dump = new XML::Dumper;
	
	$logger->info(" - Info: Serialize to XML and save in a file");
	$xml  = $dump->pl2xml( $surveyH );
	$perl = $dump->xml2pl( $xml );
	$dump->pl2xml( $perl, dirname(dirname abs_path $0) . "/Script/SSL/root/Output/$folderName/" . $xmlfile.".xml" );
}


