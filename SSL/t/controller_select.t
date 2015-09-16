use strict;
use warnings;
use Test::More;


use Catalyst::Test 'SSL';
use SSL::Controller::select;

ok( request('/select')->is_success, 'Request should succeed' );
done_testing();
