use strict;
use warnings;
use 5.010;

use Test::Simple tests => 2;

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Libs';
use CheckContent qw(check_content);

my $contentreturn="";
ok( check_content("www.ubs.com") eq $contentreturn);

