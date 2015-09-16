use strict;
use warnings;
use Test::More;


use Catalyst::Test 'SSL';
use SSL::Controller::form;

ok( request('/form')->is_success, 'Request should succeed' );
done_testing();
