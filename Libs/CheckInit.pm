=head1 NAME

check_init - Check the initial script configuration

=head1 SYNOPSIS

	my @hosts = check_init($xmlListe, $protoCipherFile, \@moduleList);

=head1 DESCRIPTION

This Module check the following items

=head2 Methods

=over 12

=item Arguments

$xmlListe		# XML BDD file path
$protoCipherFile	# .ini file path
\@moduleList		# Array ref with the lis of used Module in the script

=item Return

return \@hosts		# return the Array ref of DOM XML elements

=back

=head1 AUTHOR

Ameti Behar 

=cut

package CheckInit;

use Log::Log4perl;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(check_init);

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

sub check_init{
	my ( $xmlListe, $protoCipherFile, $moduleListR ) = @_;

	my @moduleList = @$moduleListR;

	check_exist_folder_file(\$xmlListe, \$protoCipherFile);
	
	foreach my $module (@moduleList){		
		if (!try_load_module($module)) {die "Missing module : " . $module ."\n";}
	}

	$logger->info(" - Checking XML hosts file.");
	# XML file parsing to retrieve hosts informations
	my $parser = XML::LibXML->new;
	my $dom = $parser->parse_file($xmlListe);
	my @hosts = $dom->getElementsByTagName("host");
	if(!@hosts){die "file " . $xmlListe . " existe but is empty" ;}
	
	return \@hosts;
}

sub check_exist_folder_file{
	my ($xmlListe, $protoCipherFile) = @_;
	$logger->info(" - Checking Script init.");
	if(!-d "BDD",){die "Folder BDD don't exist. Can't continue\n";}
	if(!-d "ini",){die "Folder ini don't exist. Can't contine\n";}
	if(!-d "SSL/root/Output"){
		$logger->warn(" - Folder Output don't exist. Creating foler");
		mkdir "Output";
	}
	if (-d "Libs") {
    		if (is_folder_empty("Libs")) {die "Folder Libs contain no module. Can't continue\n";}
	}
	else{
		die "Folder Libs don't exist. Can't continue\n";
	}
	if(!-f $$xmlListe, ){ die "Hosts list don't exist. Can't contiue the script\n";}
	if(!-f $$protoCipherFile, ){ die "Protocol and Cipher list don't exist. Can't contiue the script\n";}
}

sub is_folder_empty {
    my $dirname = shift;
    opendir(my $dh, $dirname) or die "Not a directory";
    return scalar(grep { $_ ne "." && $_ ne ".." } readdir($dh)) == 0;
}

sub try_load_module {
	my $mod = shift;

	eval("use $mod");

	if ($@) {
		return(0);
	} else {
		return(1);
	}
}
1;
