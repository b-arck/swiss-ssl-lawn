#!/usr/bin/perl

use strict;
use warnings;

# --- Perl Module used in the script
use Getopt::Long;
use XML::LibXML;
use Data::Dumper;
use Socket;

use Net::SSLeay qw/XN_FLAG_RFC2253 ASN1_STRFLGS_ESC_MSB/;

use Config::IniFiles;

use IO::Socket::SSL;

use Time::gmtime;

use Time::ParseDate;



Net::SSLeay::load_error_strings();

Net::SSLeay::SSLeay_add_ssl_algorithms();

Net::SSLeay::randomize();

# --- Fonctions used in the script

sub check_port {

	my ( $host, $port ) = @_;



	print "#### connect to host=$host, port=$port - ";

	warn "Info: checking port\n";


	if ( $port =~ /\D/ ) {

		$port = getservbyname( $port, 'tcp' );

	}

	die "No port" unless $port;



	my $iaddr = inet_aton($host) || die "no host: $host";

	my $paddr = sockaddr_in( $port, $iaddr );

	my $proto = getprotobyname('tcp');



	socket( SOCK, PF_INET, SOCK_STREAM, $proto ) || die "socket: $!";

	if ( connect( SOCK, $paddr ) ) {

		print "OK\n";

		close(SOCK) || die "close: $!";

		return 1;

	} else {

		print "Connection refused\n";

		return 0;

	}

}

sub check_hostname {

	warn "Info: checking hostname\n";


	# Verify hostname / CN Name

	my ( $host, $port ) = @_;

	my %server_options = (

		PeerAddr => $host,

		PeerPort => $port

	);



	if ( my $client = IO::Socket::SSL->new(%server_options) ) {

		if ( !$client->verify_hostname( $host, 'http' ) ) {

			print "Hostname verification failed\n";

			return 1;

		} else {

			print "Certificate CN: "

			  . $client->peer_certificate('commonName')

			  . " == Hostname: $host\n";



			return 0;

		}

	}

	return -1;

}


# --- "Module" used in the script


sub get_cert_details {
		my $x509 = shift;
	 	my $cert = {};
	 	my $flag_rfc22536_utf8 = (XN_FLAG_RFC2253) & (~ ASN1_STRFLGS_ESC_MSB);

	 	die 'ERROR: $x509 is NULL, gonna quit' unless $x509;

	 	warn "Info: dumping subject\n";
		 my $subj_name = Net::SSLeay::X509_get_subject_name($x509);
		 my $subj_count = Net::SSLeay::X509_NAME_entry_count($subj_name);
		 $cert->{subject}->{count} = $subj_count;
		 $cert->{subject}->{oneline} = Net::SSLeay::X509_NAME_oneline($subj_name);
		 $cert->{subject}->{print_rfc2253} = Net::SSLeay::X509_NAME_print_ex($subj_name);
		 $cert->{subject}->{print_rfc2253_utf8} = Net::SSLeay::X509_NAME_print_ex($subj_name, $flag_rfc22536_utf8);
		 $cert->{subject}->{print_rfc2253_utf8_decoded} = Net::SSLeay::X509_NAME_print_ex($subj_name, $flag_rfc22536_utf8, 1);
		 for my $i (0..$subj_count-1) {
		 	my $entry = Net::SSLeay::X509_NAME_get_entry($subj_name, $i);
		 	my $asn1_string = Net::SSLeay::X509_NAME_ENTRY_get_data($entry);
		 	my $asn1_object = Net::SSLeay::X509_NAME_ENTRY_get_object($entry);
		 	my $nid = Net::SSLeay::OBJ_obj2nid($asn1_object);
		 	$cert->{subject}->{entries}->[$i] = {
			oid  => Net::SSLeay::OBJ_obj2txt($asn1_object,1),
			data => Net::SSLeay::P_ASN1_STRING_get($asn1_string),
			data_utf8_decoded => Net::SSLeay::P_ASN1_STRING_get($asn1_string, 1),
			nid  => ($nid>0) ? $nid : undef,
			ln   => ($nid>0) ? Net::SSLeay::OBJ_nid2ln($nid) : undef,
			sn   => ($nid>0) ? Net::SSLeay::OBJ_nid2sn($nid) : undef,};
	  	}

		warn "Info: dumping issuer\n";
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

		warn "Info: dumping alternative names\n";
		$cert->{subject}->{altnames} = [ Net::SSLeay::X509_get_subjectAltNames($x509) ];

		warn "Info: dumping hashes/fingerprints\n";
		$cert->{hash}->{subject} = { dec=>Net::SSLeay::X509_subject_name_hash($x509), hex=>sprintf("%X",Net::SSLeay::X509_subject_name_hash($x509)) };
		$cert->{hash}->{issuer}  = { dec=>Net::SSLeay::X509_issuer_name_hash($x509),  hex=>sprintf("%X",Net::SSLeay::X509_issuer_name_hash($x509)) };
		$cert->{hash}->{issuer_and_serial} = { dec=>Net::SSLeay::X509_issuer_and_serial_hash($x509), hex=>sprintf("%X",Net::SSLeay::X509_issuer_and_serial_hash($x509)) };
		$cert->{fingerprint}->{md5}  = Net::SSLeay::X509_get_fingerprint($x509, "md5");
		$cert->{fingerprint}->{sha1} = Net::SSLeay::X509_get_fingerprint($x509, "sha1");
		my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1");
		$cert->{digest_sha1}->{pubkey} = Net::SSLeay::X509_pubkey_digest($x509, $sha1_digest);
		$cert->{digest_sha1}->{x509} = Net::SSLeay::X509_digest($x509, $sha1_digest);

		warn "Info: dumping expiration\n";
		$cert->{not_before} = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notBefore($x509));
		$cert->{not_after}  = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notAfter($x509));

		warn "Info: dumping serial number\n";
		my $ai = Net::SSLeay::X509_get_serialNumber($x509);
		$cert->{serial} = {
			hex  => Net::SSLeay::P_ASN1_INTEGER_get_hex($ai),
			dec  => Net::SSLeay::P_ASN1_INTEGER_get_dec($ai),
			long => Net::SSLeay::ASN1_INTEGER_get($ai),};
		$cert->{version} = Net::SSLeay::X509_get_version($x509);

		warn "Info: dumping extensions\n";
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

		warn "Info: dumping CDP\n";
		$cert->{cdp} = [ Net::SSLeay::P_X509_get_crl_distribution_points($x509) ];
		warn "Info: dumping extended key usage\n";
		$cert->{extkeyusage} = {
			oid => [ Net::SSLeay::P_X509_get_ext_key_usage($x509,0) ],
			nid => [ Net::SSLeay::P_X509_get_ext_key_usage($x509,1) ],
			sn  => [ Net::SSLeay::P_X509_get_ext_key_usage($x509,2) ],
			ln  => [ Net::SSLeay::P_X509_get_ext_key_usage($x509,3) ],};

		warn "Info: dumping key usage\n";
		$cert->{keyusage} = [ Net::SSLeay::P_X509_get_key_usage($x509) ];
		warn "Info: dumping netscape cert type\n";
		$cert->{ns_cert_type} = [ Net::SSLeay::P_X509_get_netscape_cert_type($x509) ];

		warn "Info: dumping other info\n";
		$cert->{certificate_type} = Net::SSLeay::X509_certificate_type($x509);
		$cert->{signature_alg} = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_signature_alg($x509));
		$cert->{pubkey_alg} = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_pubkey_alg($x509));
		$cert->{pubkey_size} = Net::SSLeay::EVP_PKEY_size(Net::SSLeay::X509_get_pubkey($x509));
		$cert->{pubkey_bits} = Net::SSLeay::EVP_PKEY_bits(Net::SSLeay::X509_get_pubkey($x509));
		$cert->{pubkey_id} = Net::SSLeay::EVP_PKEY_id(Net::SSLeay::X509_get_pubkey($x509));

		return $cert;
	}

# --- Script varaibles

my $xmlListe = "BDD/listSites.xml";
my $host;
my $port;
my $element ={};
my @listeElement;

# --- Script test init

if(!-e $xmlListe){ die "XML file don't exist or unavailable.\n";}

# --- XML file parsing to retrieve hosts information

my $parser = XML::LibXML->new;
my $dom = $parser->parse_file($xmlListe);

my @hosts = $dom->getElementsByTagName("host");
	
# --- Main script
foreach my $host (@hosts) {
	$port = $host->getAttribute("port");
	$host = $host->firstChild->data;
	
	if ( check_port( $host, $port ) ) {
		my $sock = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp') or die "ERROR: cannot create socket";
		my $ctx = Net::SSLeay::CTX_new() or die "ERROR: CTX_new failed";
		Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
		my $ssl = Net::SSLeay::new($ctx) or die "ERROR: new failed";
		Net::SSLeay::set_fd($ssl, fileno($sock)) or die "ERROR: set_fd failed";
		Net::SSLeay::connect($ssl) or die "ERROR: connect failed";
		my $x509 = Net::SSLeay::get_peer_certificate($ssl);

		my $cert_details = get_cert_details($x509);
	}#if check_port
}#foreach host

# --- Programme principal
