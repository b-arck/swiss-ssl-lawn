use strict;
use warnings;
use Test::More;


use Catalyst::Test 'SSL';
use SSL::Controller::loadxml;

ok( request('/loadxml')->is_success, 'Request should succeed' );
done_testing();
