use Moose;
use XML::Dumper;
use namespace::autoclean;
use List::MoreUtils qw(uniq);
use CGI;
use Data::Dumper;
use File::stat;
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/SSL/root/lib/Classes';
use Survey;
use File::Slurp qw(read_dir);

my $mylastDir = lastBDD();
my $xmlData = {};
my $dir_name = dirname(dirname abs_path $0)."/SSL/root/Output/$mylastDir";
my $path = shift;
if ( not defined $dir_name ) {
    die qq(Usage: $0 <directory>);
}

opendir(my $dir_fh, $dir_name);

my @file_list;
while ( my $file = readdir $dir_fh) {
    if ( $file !~ /^\./ ) {
	print "$file - ";	
	my $dump = new XML::Dumper;
	my $perl = $dump->xml2pl("$dir_name/$file");
	print $perl->get_cert()->{pubkey_bits};
	print "\n";
	push @file_list, "$dir_name/$file"
    }
}
closedir $dir_fh;


sub lastBDD{

	my @dir_list;
	my $directory;
	my $root = dirname(dirname abs_path $0) . '/SSL/root/Output';
	for my $dir (grep { -d "$root/$_" } read_dir($root)) {
		push @dir_list, "$dir";
	}

	return $dir_list[0];
}


