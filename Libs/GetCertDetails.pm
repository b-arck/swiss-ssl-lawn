=head1 NAME

GetCertDetails - Module to get certificate details 

=head1 SYNOPSIS

	use GetCertDetails qw(check_protocol_cipher);

	$cert_details = get_cert_details( $host, $port );

=head1 DESCRIPTION

This module get the host certificate and extract all informations.

=over 12

=item subject
=item issuer
=item alternative names
=item hashes/fingerprints
=item expiration date
=item serial number
=item version
=item extensions (oid, nid, ln, sn, data)
=item crl_distribution_points
=item extended key usage
=item netscape cert type\n";
=item certificate, signature and public key info\n";
=item certificate in .pem format

=back

=head2 Methods

=over 12

=item Arguments

$host		# The host name
$port		# The host port for connection

=item Return

A COMPLETER

=back

=head1 AUTHOR

Ameti Behar 

=cut

package GetCertDetails;

use Time::gmtime;

use Time::ParseDate;
use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(get_cert_details);

# --- Import created module used in the script

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . '/Script/Libs';
use CheckOCSP qw(check_ocsp);
use Log::Log4perl;

# Initialize Logger
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
	$logger->info(" - Info: Open connection for getting certificate details.");

	my $sock = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp') or $logger->fatal(" - Fatal: cannot create socket on port : \"$port\""),  die "ERROR: cannot create socket";
 
	my $ctx = Net::SSLeay::CTX_new() or die "ERROR: CTX_new failed";
	Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
	my $ssl = Net::SSLeay::new($ctx) or die "ERROR: new failed";
	Net::SSLeay::set_fd($ssl, fileno($sock)) or die "ERROR: set_fd failed";
	Net::SSLeay::connect($ssl) or die "ERROR: connect failed";
	my $x509 = Net::SSLeay::get_peer_certificate($ssl);

 	$logger->fatal(" - Fatal: \$x509 is NULL, gonna quit"),die 'ERROR: $x509 is NULL, gonna quit' unless $x509;

	$logger->info(" - Info: dumping subject");
	my $subj_name = Net::SSLeay::X509_get_subject_name($x509);
	my $subj_count = Net::SSLeay::X509_NAME_entry_count($subj_name);
	$cert->{subject}->{count} = $subj_count;
	$cert->{subject}->{oneline} = Net::SSLeay::X509_NAME_oneline($subj_name);
	
	$logger->info(" - Info: dumping issuer");
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

	$logger->info(" - Info: dumping alternative names");
	$cert->{subject}->{altnames} = [ Net::SSLeay::X509_get_subjectAltNames($x509) ];

	$logger->info(" - Info: dumping hashes/fingerprints");
	$cert->{hash}->{subject} = { dec=>Net::SSLeay::X509_subject_name_hash($x509), hex=>sprintf("%X",Net::SSLeay::X509_subject_name_hash($x509)) };
	$cert->{hash}->{issuer}  = { dec=>Net::SSLeay::X509_issuer_name_hash($x509),  hex=>sprintf("%X",Net::SSLeay::X509_issuer_name_hash($x509)) };
	$cert->{hash}->{issuer_and_serial} = { dec=>Net::SSLeay::X509_issuer_and_serial_hash($x509), hex=>sprintf("%X",Net::SSLeay::X509_issuer_and_serial_hash($x509)) };
	$cert->{fingerprint}->{md5}  = Net::SSLeay::X509_get_fingerprint($x509, "md5");
	$cert->{fingerprint}->{sha1} = Net::SSLeay::X509_get_fingerprint($x509, "sha1");
	my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1");
	$cert->{digest_sha1}->{pubkey} = Net::SSLeay::X509_pubkey_digest($x509, $sha1_digest);
	$cert->{digest_sha1}->{x509} = Net::SSLeay::X509_digest($x509, $sha1_digest);

	$logger->info(" - Info: dumping expiration");
	$cert->{not_before} = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notBefore($x509));
	$cert->{not_after}  = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notAfter($x509));
	$logger->info(" - Info: Cheking expiration date");
	$cert->{expiration} =check_dates($cert->{not_before},$cert->{not_after});
	
	$logger->info(" - Info: dumping serial number");
	my $ai = Net::SSLeay::X509_get_serialNumber($x509);
	$cert->{serial} = {
		hex  => Net::SSLeay::P_ASN1_INTEGER_get_hex($ai),
		dec  => Net::SSLeay::P_ASN1_INTEGER_get_dec($ai),
		long => Net::SSLeay::ASN1_INTEGER_get($ai),};
	$cert->{version} = Net::SSLeay::X509_get_version($x509);

	$logger->info(" - Info: dumping extensions");
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

	$logger->info(" - Info: dumping CRL distribution points");
	$cert->{crl}->{distrib_point} = Net::SSLeay::P_X509_get_crl_distribution_points($x509);
	
	$logger->info(" - Info: checking CRL validity");
	if( &Net::SSLeay::X509_STORE_set_flags
                (&Net::SSLeay::CTX_get_cert_store($ctx),
                 &Net::SSLeay::X509_V_FLAG_CRL_CHECK)){
		$cert->{crl}->{validity} = "CRL check valid";
	}else{
		$cert->{crl}->{validity} = "CRL check not valid";
	}

	$logger->info(" - Info: dumping extended key usage");
	$cert->{extkeyusage} = {
		oid => Net::SSLeay::P_X509_get_ext_key_usage($x509,0),
		nid => Net::SSLeay::P_X509_get_ext_key_usage($x509,1),
		sn  => Net::SSLeay::P_X509_get_ext_key_usage($x509,2),
		ln  => Net::SSLeay::P_X509_get_ext_key_usage($x509,3),};

	$logger->info(" - Info: dumping key usage");
	$cert->{keyusage} = Net::SSLeay::P_X509_get_key_usage($x509);

	$logger->info(" - Info: dumping netscape cert type");
	$cert->{ns_cert_type} = Net::SSLeay::P_X509_get_netscape_cert_type($x509);

	$logger->info(" - Info: dumping other info");
	$cert->{certificate_type} = Net::SSLeay::X509_certificate_type($x509);
	$cert->{signature_alg} = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_signature_alg($x509));
	$cert->{pubkey_alg} = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_pubkey_alg($x509));
	$cert->{pubkey_size} = Net::SSLeay::EVP_PKEY_size(Net::SSLeay::X509_get_pubkey($x509));
	$cert->{pubkey_bits} = Net::SSLeay::EVP_PKEY_bits(Net::SSLeay::X509_get_pubkey($x509));
	eval{$cert->{pubkey_id} = Net::SSLeay::EVP_PKEY_id(Net::SSLeay::X509_get_pubkey($x509))};
	
	
	$logger->info(" - Info: dumping pem");
	my $pem = Net::SSLeay::PEM_get_string_X509($x509);
	
	$logger->info(" - Info: dumping OCSP info");
	eval{$cert->{ocsp} = check_ocsp( $ssl, $x509 )};
	if(!$cert->{ocsp}){$cert->{ocsp}; $cert->{ocsp}="OCSP not valid"; print $cert->{ocsp};}
	
	$logger->info(" - Info: Closing connection for getting certificate details.");
	Net::SSLeay::free($ssl);                   
	Net::SSLeay::CTX_free($ctx);

	return $pem, $cert ;
}

sub check_dates {
	my ( $date_before, $date_after ) = @_;

	my $date_before_epoch = parsedate($date_before);
	my $date_after_epoch  = parsedate($date_after);
	my $date_now_epoch    = time();

	if ( $date_before_epoch > $date_now_epoch ) {
		return "Certificate not yet valid\n";
	} elsif ( $date_after_epoch <= $date_now_epoch ) {
		return "Certificate expired\n";
	} elsif ( $date_after_epoch <= ( $date_now_epoch + ( 30 * 24 * 60 * 60 ) ) ){
		return "Certificate will expire in 30 days or less\n";
	} else {
		return "Certificate date valid\n";
	}
}
1;
