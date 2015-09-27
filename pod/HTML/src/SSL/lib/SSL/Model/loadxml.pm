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

sub loadAllData {
	my $dump = new XML::Dumper;
	my $perl = $dump->xml2pl(lastBDD());
	
	my $xmlData = {};
	my $i = 0;
	foreach my $element (values($perl)) {
		bless $element, 'Survey';
		$xmlData->{$i} = $element;
		$i++;
	}
	return $xmlData;
}

sub loadDetails{
	my ($self, $args) = @_;

	my $dump = new XML::Dumper;
	my $perl = $dump->xml2pl(lastBDD());
	
	my $xmlData = {};
	my $id;
	my $site;
	my $i = 0;
	my @fields = split('/', $args);
	foreach my $element (values($perl)) {
		bless $element, 'Survey';
		if( ($element->get_id() == $fields[2]) and ($element->get_hostName() eq $fields[3]) ){
			$xmlData->{$i} = $element;
		}	
		$i++;
	}
	return $xmlData;
}

sub loadSiteByType{
	my ($self, $args) = @_;

	my $dump = new XML::Dumper;
	my $perl = $dump->xml2pl(lastBDD());
	
	my $xmlData = {};
	my $i = 0;
	my @fields = split('/', $args);
	foreach my $element (values($perl)) {
		bless $element, 'Survey';
		if($fields[1] ne "all"){
			
			if( $element->get_hostType() eq $fields[1]){
				$xmlData->{$i} = $element;
			}	
			$i++;
		}
		else{
			$xmlData->{$i} = $element;
			$i++;
		}
	}
	return $xmlData;
}

sub loadSortedType{
	my ($self, $args) = @_;

	my $dump = new XML::Dumper;
	my $perl = $dump->xml2pl(lastBDD());
	
	my $xmlData = {};
	my $Data = {};
	my $i = 0;
	my @fields = split('/', $args);
	foreach my $element (values($perl)) {
		bless $element, 'Survey';
		if($fields[2] ne "all"){
			if( $element->get_hostType() eq $fields[2]){
				$xmlData->{$i} = $element;
			}	
			$i++;
		}
		else{
			$xmlData->{$i} = $element;
			$i++;
		}
	}

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
	return $Data;
}

sub lastBDD{

	my $dir_name = dirname(dirname abs_path $0)."/root/Output";
	my $path = shift;
	if ( not defined $dir_name ) {
	    die qq(Usage: $0 <directory>);
	}

	opendir(my $dir_fh, $dir_name);

	my @file_list;
	while ( my $file = readdir $dir_fh) {
	    if ( $file !~ /^\./ ) {
		push @file_list, "$dir_name/$file"
	    }
	}
	closedir $dir_fh;

	for my $file (sort {
		my $a_stat = stat($a);
		my $b_stat = stat($b);
		$a_stat->ctime <=> $b_stat->ctime;
	    }  @file_list ) {
		$path = $file;
	}
	return $path;
}

sub findType{

	my @data;
	my @listType;
	my $dump = new XML::Dumper;
	my $perl = $dump->xml2pl(lastBDD());
	my $i=0;
	foreach my $element (values($perl)) {
		bless $element, 'Survey';
		$data[$i] = $element->get_hostType();
		$i++;
	}

	@listType = uniq(@data);
	return \@listType;
}

sub drawChart{
my ($self, $args) = @_;

	my @fields = split('/', $args);
	my $site=$fields[2];
	my $data = {};
	my $dir_name = dirname(dirname abs_path $0)."/root/Output";
	my $path = shift;
	if ( not defined $dir_name ) {
	    die qq(Usage: $0 <directory>);
	}

	opendir(my $dir_fh, $dir_name);

	my @file_list;
	while ( my $file = readdir $dir_fh) {
	    if ( $file !~ /^\./ ) {
		push @file_list, "$dir_name/$file"
	    }
	}
	closedir $dir_fh;
	my $i=0;
	foreach my $file((sort {my $a_stat = stat($a);my $b_stat = stat($b);$a_stat->ctime <=> $b_stat->ctime;}  @file_list )){
		my $dump = new XML::Dumper;
		my $perl = $dump->xml2pl($file);
		foreach my $element (values($perl)) {

			if( $site eq $element->get_hostName()){
				my $date = $element->get_date();
				my $result = $element->get_result();
				my $color = getColor($result);
				$data->{$i} = "['$date', $result, 'color : $color']";
				$i++;
			}	
		}
	}

	return $data;
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
