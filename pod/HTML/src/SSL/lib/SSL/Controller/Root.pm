package SSL::Controller::Root;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller' }

__PACKAGE__->config(namespace => '');

=encoding utf-8

=head1 NAME

SSL::Controller::Root - Root Controller for SSL

=head1 DESCRIPTION

This controller display the index page with complet audit list

=head1 METHODS

=head2 index

The root page (/)

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    $c->stash->{menu} = $c->model('loadxml')->findType();
    $c->stash->{hashref} = $c->model('loadxml')->loadAllData();
    $c->stash(type => 'all');
    $c->stash->{template} = 'index.tt2';
    $c->forward($c->view('HTML'));
}

=head2 default

Standard 404 error page

=cut

sub default :Path {
    my ( $self, $c ) = @_;
    $c->stash->{template} = 'notfound.tt2';
    $c->response->status(404);
}

=head2 end

Attempt to render a view, if needed.

=cut

sub end : ActionClass('RenderView') {}

=head1 AUTHOR

Behar Ameti,,,

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;
