### client side
use Net::SSLeay;
use IO::Socket::INET;

Net::SSLeay::initialize();
my $sock = IO::Socket::INET->new(PeerAddr=>'encrypted.google.com:443') or die;
my $ctx = Net::SSLeay::CTX_tlsv1_new() or die;
Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
Net::SSLeay::CTX_set_next_proto_select_cb($ctx, ['http1.1','spdy/2']);
my $ssl = Net::SSLeay::new($ctx) or die;
Net::SSLeay::set_fd($ssl, fileno($sock)) or die;
Net::SSLeay::connect($ssl);

warn "client:negotiated=",Net::SSLeay::P_next_proto_negotiated($ssl), "\n";
warn "client:last_status=", Net::SSLeay::P_next_proto_last_status($ssl), "\n";
