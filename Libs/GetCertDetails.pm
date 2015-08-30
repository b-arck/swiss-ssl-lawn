=head1 NAME

GetCertDetails - Get certificate details 

=head1 SYNOPSIS

	use GetCertDetails qw(check_protocol_cipher);

	$cert_details = get_cert_details( $host, $port );

=head1 DESCRIPTION

This module get the host certificate and extract all informations.

=over 12

=item Subject
=item Issuer
=item Alternative names
=item Ashes/fingerprints
=item Expiration date
=item Serial number
=item Version
=item Extensions (oid, nid, ln, sn, data)
=item CRL distribution points
=item Extended key usage
=item Netscape cert type
=item Certificate, signature and public key info
=item Certificate in .pem format
=item OCSP info and OCSP validation 

=back

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port

=item Return

return $cert;	# Hash ref with all certificate inforation

=back

=head1 AUTHOR

Ameti Behar 

=cut

package GetCertDetails;

use Time::gmtime;
use Time::ParseDate;
use Log::Log4perl;
use Exporter;

use Net::SSLeay qw/XN_FLAG_RFC2253 ASN1_STRFLGS_ESC_MSB/;
	
@ISA = qw(Exporter);
@EXPORT = qw(get_cert_details);

# --- Import created module used in the script

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Libs';
use CheckOCSP qw(check_ocsp);

# --- Initialize logging info message for debug
my $log_conf = q(
   log4perl.rootLogger              = INFO, LOG1
   log4perl.appender.LOG1           = Log::Log4perl::Appender::File
   log4perl.appender.LOG1.filename  = ./Log/logfile.log
   log4perl.appender.LOG1.mode      = append
   log4perl.appender.LOG1.layout    = Log::Log4perl::Layout::PatternLayout
   log4perl.appender.LOG1.layout.ConversionPattern = %d %p %m %n
);
Log::Log4perl::init(\$log_conf);
my $logger = Log::Log4perl->get_logger();

sub get_cert_details {
	my ( $host, $port ) = @_;

	
 	my $cert = {};
 	my $flag_rfc22536_utf8 = (XN_FLAG_RFC2253) & (~ ASN1_STRFLGS_ESC_MSB);
	$logger->info(" - Open connection for getting certificate details.");

	Net::SSLeay::randomize();
	Net::SSLeay::load_error_strings();
	Net::SSLeay::ERR_load_crypto_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();

	my $sock = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp') 
		or $logger->fatal(" - Cannot create socket on port : \"$port\" for host : \"$host\""),  
		die "ERROR: cannot create socket";
 
	my $ctx = Net::SSLeay::CTX_new() or die "ERROR: CTX_new failed";
	Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
	my $ssl = Net::SSLeay::new($ctx) or die "ERROR: new failed";
	Net::SSLeay::set_fd($ssl, fileno($sock)) or die "ERROR: set_fd failed";
	
	eval{
	Net::SSLeay::connect($ssl) or die "ERROR: connect failed";
	my $x509 = Net::SSLeay::get_peer_certificate($ssl);

 	$logger->fatal(" - \$x509 is NULL, gonna quit"),die 'ERROR: $x509 is NULL, gonna quit' unless $x509;

	$logger->info(" - Dumping subject");
	my $subj_name = Net::SSLeay::X509_get_subject_name($x509);
	my $subj_count = Net::SSLeay::X509_NAME_entry_count($subj_name);
	$cert->{subject}->{count} = $subj_count;
	$cert->{subject}->{oneline} = Net::SSLeay::X509_NAME_oneline($subj_name);
	
	$logger->info(" - Dumping issuer");
	my $issuer_name = Net::SSLeay::X509_get_issuer_name($x509);
	my $issuer_count = Net::SSLeay::X509_NAME_entry_count($issuer_name);
	$cert->{issuer}->{count} = $issuer_count;
	$cert->{issuer}->{oneline} = Net::SSLeay::X509_NAME_oneline($issuer_name);
	$cert->{issuer}->{print_rfc2253} = Net::SSLeay::X509_NAME_print_ex($issuer_name);
	$cert->{issuer}->{print_rfc2253_utf8} = Net::SSLeay::X509_NAME_print_ex($issuer_name, $flag_rfc22536_utf8);
	$cert->{issuer}->{print_rfc2253_utf8_decoded} = Net::SSLeay::X509_NAME_print_ex($issuer_name, $flag_rfc22536_utf8, 1);
	for my $i (0..$issuer_count-1) {
		my $entry = Net::SSLeay::X509_NAME_get_entry($issuer_name, $i);
		my $asn1_string = Net::SSLeay::X509_NAME_ENTRY_get_data($entry);
		my $asn1_object = Net::SSLeay::X509_NAME_ENTRY_get_object($entry);
		my $nid = Net::SSLeay::OBJ_obj2nid($asn1_object);
		$cert->{issuer}->{entries}->[$i] = {
		oid  => Net::SSLeay::OBJ_obj2txt($asn1_object,1),
		data => Net::SSLeay::P_ASN1_STRING_get($asn1_string),
		data_utf8_decoded => Net::SSLeay::P_ASN1_STRING_get($asn1_string, 1),
		nid  => ($nid>0) ? $nid : undef,
		ln   => ($nid>0) ? Net::SSLeay::OBJ_nid2ln($nid) : undef,
		sn   => ($nid>0) ? Net::SSLeay::OBJ_nid2sn($nid) : undef,};
	}

	$logger->info(" - Dumping alternative names");
	$cert->{subject}->{altnames} = [ Net::SSLeay::X509_get_subjectAltNames($x509) ];

	$logger->info(" - Dumping hashes/fingerprints");
	$cert->{hash}->{subject} = { dec=>Net::SSLeay::X509_subject_name_hash($x509), hex=>sprintf("%X",Net::SSLeay::X509_subject_name_hash($x509)) };
	$cert->{hash}->{issuer}  = { dec=>Net::SSLeay::X509_issuer_name_hash($x509),  hex=>sprintf("%X",Net::SSLeay::X509_issuer_name_hash($x509)) };
	$cert->{hash}->{issuer_and_serial} = { dec=>Net::SSLeay::X509_issuer_and_serial_hash($x509), hex=>sprintf("%X",Net::SSLeay::X509_issuer_and_serial_hash($x509)) };
	$cert->{fingerprint}->{md5}  = Net::SSLeay::X509_get_fingerprint($x509, "md5");
	$cert->{fingerprint}->{sha1} = Net::SSLeay::X509_get_fingerprint($x509, "sha1");
	my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1");
	$cert->{digest_sha1}->{pubkey} = unpack('H*', Net::SSLeay::X509_pubkey_digest($x509, $sha1_digest))."\n";
	$cert->{digest_sha1}->{x509} = unpack('H*', Net::SSLeay::X509_digest($x509, $sha1_digest));

	$logger->info(" - Dumping expiration");
	$cert->{expiration}->{not_before} = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notBefore($x509));
	$cert->{expiration}->{not_after}  = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notAfter($x509));

	$logger->info(" - Cheking expiration date");
	$cert->{expiration}->{status} = check_dates(
		Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notBefore($x509)),
		Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notAfter($x509)));
	
	$logger->info(" - Dumping serial number");
	my $ai = Net::SSLeay::X509_get_serialNumber($x509);

	$cert->{serial} = {
		hex  => Net::SSLeay::P_ASN1_INTEGER_get_hex($ai),
		dec  => Net::SSLeay::P_ASN1_INTEGER_get_dec($ai),
		long => Net::SSLeay::ASN1_INTEGER_get($ai),
		string  => unpack('H*',Net::SSLeay::P_ASN1_STRING_get(Net::SSLeay::X509_get_serialNumber($x509))),};
	$cert->{version} = Net::SSLeay::X509_get_version($x509);

	$logger->info(" - Dumping extensions");
	my $ext_count = Net::SSLeay::X509_get_ext_count($x509);
	$cert->{extensions}->{count} = $ext_count;
	for my $i (0..$ext_count-1) {
		my $ext = Net::SSLeay::X509_get_ext($x509,$i);
		my $asn1_string = Net::SSLeay::X509_EXTENSION_get_data($ext);
		my $asn1_object = Net::SSLeay::X509_EXTENSION_get_object($ext);
		my $nid = Net::SSLeay::OBJ_obj2nid($asn1_object);
		$cert->{extensions}->{entries}->[$i] = {
			critical => Net::SSLeay::X509_EXTENSION_get_critical($ext),
			oid      => Net::SSLeay::OBJ_obj2txt($asn1_object,1),
			nid      => ($nid>0) ? $nid : undef,
			ln       => ($nid>0) ? Net::SSLeay::OBJ_nid2ln($nid) : undef,
			sn       => ($nid>0) ? Net::SSLeay::OBJ_nid2sn($nid) : undef,
			data     => Net::SSLeay::X509V3_EXT_print($ext),};
	}

	$logger->info(" - Dumping CRL distribution points");
	$cert->{crl}->{distrib_point} = Net::SSLeay::P_X509_get_crl_distribution_points($x509);

	$logger->info(" - Dumping extended key usage");
	$cert->{extkeyusage} = {
		oid => Net::SSLeay::P_X509_get_ext_key_usage($x509,0),
		nid => Net::SSLeay::P_X509_get_ext_key_usage($x509,1),
		sn  => Net::SSLeay::P_X509_get_ext_key_usage($x509,2),
		ln  => Net::SSLeay::P_X509_get_ext_key_usage($x509,3),};

	$logger->info(" - Dumping key usage");
	$cert->{keyusage} = Net::SSLeay::P_X509_get_key_usage($x509);

	$logger->info(" - Dumping netscape cert type");
	$cert->{ns_cert_type} = Net::SSLeay::P_X509_get_netscape_cert_type($x509);

	$logger->info(" - Dumping other info");
	$cert->{certificate_type} = Net::SSLeay::X509_certificate_type($x509);
	$cert->{signature_alg} = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_signature_alg($x509));
	$cert->{pubkey_alg} = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_pubkey_alg($x509));
	$cert->{pubkey_size} = Net::SSLeay::EVP_PKEY_size(Net::SSLeay::X509_get_pubkey($x509));
	$cert->{pubkey_bits} = Net::SSLeay::EVP_PKEY_bits(Net::SSLeay::X509_get_pubkey($x509));
	eval{$cert->{pubkey_id} = Net::SSLeay::EVP_PKEY_id(Net::SSLeay::X509_get_pubkey($x509))};
	
	
	$logger->info(" - Dumping pem");
	$cert->{pem} = Net::SSLeay::PEM_get_string_X509($x509);

	$logger->info(" - Dumping OCSP info and OCSP validation");
	$cert->{ocsp} = "";
	eval{$cert->{ocsp} = check_ocsp( $ssl, $x509 )};
	
	$logger->info(" - Closing connection for getting certificate details.");
	Net::SSLeay::free($ssl);                   
	Net::SSLeay::CTX_free($ctx);
	close($ssl);
	$cert->{score} = cert_score($cert);

	return $cert ;
	}
}

sub check_dates {
	my ( $date_before, $date_after ) = @_;

	my $date_before_epoch = parsedate($date_before);
	my $date_after_epoch  = parsedate($date_after);
	my $date_now_epoch    = time();

	if ( $date_before_epoch > $date_now_epoch ) {
		return "Certificate not yet valid";
	} elsif ( $date_after_epoch <= $date_now_epoch ) {
		return "Certificate expired";
	} elsif ( $date_after_epoch <= ( $date_now_epoch + ( 30 * 24 * 60 * 60 ) ) ){
		return "Certificate will expire in 30 days or less";
	} else {
		return "Certificate date valid";
	}
}

sub cert_score{
	my ( $cert ) = @_;
	
	my $score = 100;

	if(($cert->{expiration}->{status} eq "Certificate expired" or 
		$cert->{expiration}->{status} eq "Certificate not yet valid") 
		or ($cert->{signature_alg} =~ m/md5/ or $cert->{signature_alg} =~ m/md2/)
		or $cert->{ocsp} eq "OCSP certificate status is REVOKED"
		or $cert->{pubkey_size} < 128 ){

		return 0;

	} elsif ($cert->{ocsp} =~ m/faild/) {
		$score -= 10;
	} elsif ($cert->{pubkey_bits} < pubkey_bits){
		$score -=10;
	}
	
	return $score;
}
1;
