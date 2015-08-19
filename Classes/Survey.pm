=head1 NAME

Survey - Class 

=head1 SYNOPSIS

    use Survey;

    my $audit = Survey->new();

=head1 DESCRIPTION

This class is used to store information about web site survey

=head2 Attributes

	$this->{_ID}		= $ref_arguments->{id};
	$this->{_HOSTNAME}	= $ref_arguments->{hostName};
	$this->{_IP}		= $ref_arguments->{ip};
	$this->{_RESULT}	= $ref_arguments->{result};
	$this->{_GRADE}         = $ref_arguments->{grade};
	$this->{_SSL}		= $ref_arguments->{ssl};
	$this->{_CERTIFICATE}	= $ref_arguments->{cert};
	$this->{_PEMCERT}	= $ref_arguments->{pemcert};
	$this->{_CONTENT}	= $ref_arguments->{content};
	$this->{_DATE}		= $ref_arguments->{date};

=head2 Methods

=over 12

=item Getter and Setter on each attribute

=item Return 

return $this;

=back

=head1 AUTHOR

Ameti Behar 
pod2html --podroot=./ --podpath=./pod --header --title="Survey" Survey.pm > Survey.html

=cut

package Survey; 
use warnings;        
use strict;          
use Carp;            

# Certificate classe constructor
sub new {
	my ( $classe, $ref_arguments ) = @_;

	# Verify classe
	$classe = ref($classe) || $classe;

	my $this = {};

	bless( $this, $classe );

	$this->{_ID}		= $ref_arguments->{id};
	$this->{_HOSTNAME}	= $ref_arguments->{hostName};
	$this->{_IP}		= $ref_arguments->{ip};
	$this->{_RESULT}	= $ref_arguments->{result};
	$this->{_GRADE}         = $ref_arguments->{grade};
	$this->{_SSL}		= $ref_arguments->{ssl};
	$this->{_CERTIFICATE}	= $ref_arguments->{cert};
	$this->{_PEMCERT}	= $ref_arguments->{pemcert};
	$this->{_CONTENT}	= $ref_arguments->{content};
	$this->{_DATE}		= $ref_arguments->{date};

	return $this;
}


sub get_id {
  my $this = shift;
  return $this->{_ID};
}

sub set_id {
  my ( $this, $id ) = @_;

  if ( defined $id ) {
    $this->{_ID} = $id;
  }

  return;
}

sub get_hostName {
  my $this = shift;
  return $this->{_HOSTNAME};
}

sub set_hostName {
  my ( $this, $host ) = @_;

  if ( defined $host ) {
    $this->{_HOSTNAME} = $host;
  }

  return;
}

sub get_ip {
  my $this = shift;
  return $this->{_IP};
}

sub set_ip {
  my ( $this, $ip ) = @_;

  if ( defined $ip ) {
    $this->{_IP} = $ip;
  }

  return;
}

sub get_result {
  my $this = shift;
  return $this->{_RESULT};
}

sub set_result {
  my ( $this, $res ) = @_;

  if ( defined $res ) {
    $this->{_RESULT} = $res;
  }

  return;
}

sub get_grade {
  my $this = shift;
  return $this->{_GRADE};
}

sub set_grade {
  my ( $this, $grade ) = @_;

  if ( defined $grade ) {
    $this->{_GRADE} = $grade;
  }

  return;
}

sub get_ssl {
  my $this = shift;
  return $this->{_SSL};
}

sub set_ssl {
  my ( $this, $ssl ) = @_;

  if ( defined $ssl ) {
    $this->{_SSL} = $ssl;
  }

  return;
}

sub get_cert {
  my $this = shift;
  return $this->{_CERTIFICATE};
}

sub set_cert {
  my ( $this, $cert ) = @_;

  if ( defined $cert ) {
    $this->{_CERTIFICATE} = $cert;
  }

  return;
}

sub get_pemcert {
  my $this = shift;
  return $this->{_PEMCERT};
}

sub set_pemcert {
  my ( $this, $pemcert ) = @_;

  if ( defined $pemcert ) {
    $this->{_PEMCERT} = $pemcert;
  }

  return;
}

sub get_content {
  my $this = shift;
  return $this->{_CONTENT};
}

sub set_content {
  my ( $this, $content ) = @_;

  if ( defined $content ) {
    $this->{_CONTENT} = $content;
  }

  return;
}

sub get_flash {
  my $this = shift;
  return $this->{_FLASH};
}

sub set_flash {
  my ( $this, $flash ) = @_;

  if ( defined $flash ) {
    $this->{_FLASH} = $flash;
  }

  return;
}

sub get_redirect {
  my $this = shift;
  return $this->{_REDIRECT};
}

sub set_redirect {
  my ( $this, $redirect ) = @_;

  if ( defined $redirect ) {
    $this->{_REDIRECT} = $redirect;
  }

  return;
}

sub get_ext {
  my $this = shift;
  return $this->{_EXT};
}

sub set_ext {
  my ( $this, $ext ) = @_;

  if ( defined $ext ) {
    $this->{_EXT} = $ext;
  }

  return;
}

sub get_date {
  my $this = shift;
  return $this->{_DATE};
}

sub set_date {
  my ( $this, $date ) = @_;

  if ( defined $date ) {
    $this->{_DATE} = $date;
  }

  return;
}

1;
__END__
