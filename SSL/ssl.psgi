use strict;
use warnings;

use SSL;

my $app = SSL->apply_default_middlewares(SSL->psgi_app);
$app;

