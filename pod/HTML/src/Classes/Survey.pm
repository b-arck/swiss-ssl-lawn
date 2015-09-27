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
	$this->{_HOSTTYPE}	= $ref_arguments->{hostType};
	$this->{_PORT}		= $ref_arguments->{port};
	$this->{_IP}		= $ref_arguments->{ip};
	$this->{_RESULT}	= $ref_arguments->{result};
	$this->{_GRADE}         = $ref_arguments->{grade};
	$this->{_SSL}		= $ref_arguments->{ssl};
	$this->{_CERTIFICATE}	= $ref_arguments->{cert};
	$this->{_TRUSTED}	= $ref_arguments->{trusted};
	$this->{_CONTENT}	= $ref_arguments->{content};
	$this->{_DATE}		= $ref_arguments->{date};

=head2 Methods

=over

=item Getter and Setter on each attribute

=back

=head2 Return

=over

=item Return 

return $this;

=back

=head1 AUTHOR

=cut

package Survey; 
use warnings;        
use strict;          
use Carp;            

# Survey classe constructor
sub new {
	my ( $classe, $ref_arguments ) = @_;

	# Verify classe
	$classe = ref($classe) || $classe;

	my $this = {};

	bless( $this, $classe );

	$this->{ID}		= $ref_arguments->{id};
	$this->{HOSTNAME}	= $ref_arguments->{hostName};
	$this->{HOSTTYPE}	= $ref_arguments->{hostType};
	$this->{PORT}		= $ref_arguments->{port};
	$this->{IP}		= $ref_arguments->{ip};
	$this->{RESULT}		= $ref_arguments->{result};
	$this->{GRADE}          = $ref_arguments->{grade};
	$this->{SSL}		= $ref_arguments->{ssl};
	$this->{CERTIFICATE}	= $ref_arguments->{cert};
	$this->{TRUSTED}	= $ref_arguments->{trusted};
	$this->{CONTENT}	= $ref_arguments->{content};
	$this->{DATE}		= $ref_arguments->{date};;

	return $this;
}


sub get_id {
  my $this = shift;
  return $this->{ID};
}

sub set_id {
  my ( $this, $id ) = @_;

  if ( defined $id ) {
    $this->{ID} = $id;
  }

  return;
}

sub get_hostName {
  my $this = shift;
  return $this->{HOSTNAME};
}

sub set_hostName {
  my ( $this, $host ) = @_;

  if ( defined $host ) {
    $this->{HOSTNAME} = $host;
  }

  return;
}

sub get_hostType {
  my $this = shift;
  return $this->{HOSTTYPE};
}

sub set_hostType {
  my ( $this, $host ) = @_;

  if ( defined $host ) {
    $this->{HOSTTYPE} = $host;
  }

  return;
}

sub get_port {
  my $this = shift;
  return $this->{PORT};
}

sub set_port {
  my ( $this, $host ) = @_;

  if ( defined $host ) {
    $this->{PORT} = $host;
  }

  return;
}

sub get_ip {
  my $this = shift;
  return $this->{IP};
}

sub set_ip {
  my ( $this, $ip ) = @_;

  if ( defined $ip ) {
    $this->{IP} = $ip;
  }

  return;
}

sub get_result {
  my $this = shift;
  return $this->{RESULT};
}

sub set_result {
  my ( $this, $res ) = @_;

  if ( defined $res ) {
    $this->{RESULT} = $res;
  }

  return;
}

sub get_grade {
  my $this = shift;
  return $this->{GRADE};
}

sub set_grade {
  my ( $this, $grade ) = @_;

  if ( defined $grade ) {
    $this->{GRADE} = $grade;
  }

  return;
}

sub get_ssl {
  my $this = shift;
  return $this->{SSL};
}

sub set_ssl {
  my ( $this, $ssl ) = @_;

  if ( defined $ssl ) {
    $this->{SSL} = $ssl;
  }

  return;
}

sub get_cert {
  my $this = shift;
  return $this->{CERTIFICATE};
}

sub set_cert {
  my ( $this, $cert ) = @_;

  if ( defined $cert ) {
    $this->{CERTIFICATE} = $cert;
  }

  return;
}

sub get_trusted {
  my $this = shift;
  return $this->{TRUSTED};
}

sub set_trusted {
  my ( $this, $trusted ) = @_;

  if ( defined $trusted ) {
    $this->{TRUSTED} = $trusted;
  }

  return;
}

sub get_content {
  my $this = shift;
  return $this->{CONTENT};
}

sub set_content {
  my ( $this, $content ) = @_;

  if ( defined $content ) {
    $this->{CONTENT} = $content;
  }

  return;
}


sub get_date {
  my $this = shift;
  return $this->{DATE};
}

sub set_date {
  my ( $this, $date ) = @_;

  if ( defined $date ) {
    $this->{DATE} = $date;
  }

  return;
}

1;
__END__
