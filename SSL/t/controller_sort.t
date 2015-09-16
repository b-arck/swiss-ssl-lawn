use strict;
use warnings;
use Test::More;


use Catalyst::Test 'SSL';
use SSL::Controller::sort;

ok( request('/sort')->is_success, 'Request should succeed' );
done_testing();
