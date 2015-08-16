#!/usr/bin/perl
use strict; use warnings;    
use Pod::HtmlEasy;   
my $pod_file = "../Libs/CheckProtocolCipher.pm" or die "Specify POD file as argument";    
my $podhtml = Pod::HtmlEasy->new();
my $html = $podhtml->pod2html( "../Classes/Survey.htm");
print $html;
