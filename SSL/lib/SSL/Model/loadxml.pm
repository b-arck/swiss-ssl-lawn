package SSL::Model::loadxml;
use Moose;
use XML::Dumper;
use namespace::autoclean;
use List::MoreUtils qw(uniq);
use CGI;
use File::stat;
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/root/lib/Classes';
use Survey;
use File::Slurp qw(read_dir);

extends 'Catalyst::Model';

=head1 NAME

SSL::Model::loadxml - Catalyst Model

=head1 DESCRIPTION

Catalyst Model that contain all function to retrieve datas.


=encoding utf8

=head1 AUTHOR

Behar Ameti,,,

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

sub loadDetails{
	my ($self, $args) = @_;
	
	
	my $mylastDir = lastBDD();
	my $xmlData = {};
	my $i = 0;
	my $id;
	my @fields = split('/', $args);
	my $dir_name = dirname(dirname abs_path $0)."/root/Output/$mylastDir";
	my $path = shift;
	if ( not defined $dir_name ) {
	    die qq(Usage: $0 <directory>);
	}

	opendir(my $dir_fh, $dir_name);

	while ( my $file = readdir $dir_fh) {
	    if ( $file !~ /^\./ ) {
		my @fname = split('/', $file);
		my $arg = $fields[3] . ".xml";
		if($file eq  $arg){
			my $dump = new XML::Dumper;
			my $perl = $dump->xml2pl("$dir_name/$file");
	
			bless $perl, 'Survey';
			$xmlData->{$i} = $perl;
			$id = $perl->get_id();
			undef($perl);
			$i++;
		}
	    }
	}
	closedir $dir_fh;

	return $xmlData, $id;
}

sub loadSiteByType{
	my ($self, $args) = @_;

	my $mylastDir = lastBDD();
	my $xmlData = {};
	my $i = 0;
	my $j = 0;
	my @data;
	my @listType;

	my @fields = split('/', $args);
	my $dir_name = dirname(dirname abs_path $0)."/root/Output/$mylastDir";
	my $path = shift;
	if ( not defined $dir_name ) {
	    die qq(Usage: $0 <directory>);
	}

	opendir(my $dir_fh, $dir_name);

	while ( my $file = readdir $dir_fh) {
	    if ( $file !~ /^\./ ) {
		eval{my $dump = new XML::Dumper;
		my $perl = $dump->xml2pl("$dir_name/$file");
	
		bless $perl, 'Survey';
		if($fields[1] ne "all"){
			
			if( $perl->get_hostType() eq $fields[1]){
				$xmlData->{$i} = $perl;
			}	
			$i++;
		}
		else{
			$xmlData->{$i} = $perl;
			$i++;
		}
		$data[$j] = $perl->get_hostType();
		$j++;
		undef($perl);}
	    }
	}
	closedir $dir_fh;
	@listType = uniq(@data);
	return $xmlData, \@listType;
}

sub loadSortedType{
	my ($self, $args) = @_;

	my $mylastDir = lastBDD();
	my $xmlData = {};
	my $Data = {};
	my $i = 0;
	my $j = 0;
	my @menu;
	my @listType;

	my @fields = split('/', $args);
	my $dir_name = dirname(dirname abs_path $0)."/root/Output/$mylastDir";
	my $path = shift;
	if ( not defined $dir_name ) {
	    die qq(Usage: $0 <directory>);
	}

	opendir(my $dir_fh, $dir_name);

	while ( my $file = readdir $dir_fh) {
	    if ( $file !~ /^\./ ) {
		eval{my $dump = new XML::Dumper;
		my $perl = $dump->xml2pl("$dir_name/$file");
	
		bless $perl, 'Survey';
		if($fields[2] ne "all"){
			
			if( $perl->get_hostType() eq $fields[2]){
				$xmlData->{$i} = $perl;
			}	
			$i++;
		}
		else{
			$xmlData->{$i} = $perl;
			$i++;
		}
		$menu[$j] = $perl->get_hostType();
		$j++;
		undef($perl);}
	    }
	}
	closedir $dir_fh;

	if($fields[1] eq "name"){
		my $j=0;
		foreach my $value (sort { lc $a->get_hostName() cmp lc $b->get_hostName() } values %$xmlData)
		{
			$Data->{$j} = $value;
			$j++
		}
	}elsif($fields[1] eq "key"){
		my $j=0;
		foreach my $value (sort { lc $a->get_cert()->{pubkey_bits} <=> $b->get_cert()->{pubkey_bits} } values %$xmlData)
		{
			$Data->{$j} = $value;
			$j++
		}
	}elsif($fields[1] eq "result"){
		my $j=0;
		foreach my $value (sort { $a->get_result() <=> $b->get_result() } values %$xmlData)
		{
			$Data->{$j} = $value;
			$j++
		}
	}
	@listType = uniq(@menu);
	return $Data, \@listType;

}

sub drawChart{
my ($self, $args) = @_;

	my $data = {};
	my $i = 0;
	my @dir_list;
	my $directory;
	my @fields = split('/', $args);
	my $site= $fields[2];
	my $dir_name = dirname(dirname abs_path $0)."/root/Output";

	for my $dir (grep { -d "$dir_name/$_" } read_dir($dir_name)) {
		push @dir_list, "$dir";
		$i++
	}

	foreach my $folder (@dir_list){
		opendir(my $dir_fh, "$dir_name/$folder");

		while ( my $file = readdir $dir_fh) {
			if ( $file !~ /^\./ ) {
				my @fname = split('/', $file);
				my $arg = $fields[2] . ".xml";
				if($file eq  $arg){
					my $dump = new XML::Dumper;
					my $perl = $dump->xml2pl("$dir_name/$folder/$file");
	
					bless $perl, 'Survey';
					my $date = $perl->get_date();
					my $result = $perl->get_result();
					my $color = getColor($result);
					$data->{$i} = "['$date', $result, 'color : $color']";
					$i--;
				}
			}
		}
		closedir $dir_fh;
	}
	return $data;
}

sub lastBDD{

	my @dir_list;
	my $directory;
	my $root = dirname(dirname abs_path $0)."/root/Output";
	for my $dir (grep { -d "$root/$_" } read_dir($root)) {
		push @dir_list, "$dir";
	}

	return $dir_list[0];
}

sub retType{
my ($self, $args) = @_;

	my @fields = split('/', $args);
	return $fields[2];
}
sub retTypeSelect{
my ($self, $args) = @_;

	my @fields = split('/', $args);
	return $fields[1];
}
sub getId{
my ($self, $args) = @_;

	my @fields = split('/', $args);
	return $fields[2];
}
sub getName{
my ($self, $args) = @_;

	my @fields = split('/', $args);
	return $fields[2];
}

sub getColor {
	my ($score, $contentScore) = @_;
	my $color;
	
	if ( $score >= 80 ) {
		$color = "green";
	} elsif ( $score >= 50 ) {
		$color = "orange";
	} else {
		$color = "red";
	}

	return ($color);
}

__PACKAGE__->meta->make_immutable;

1;
