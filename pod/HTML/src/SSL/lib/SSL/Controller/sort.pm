package SSL::Controller::sort;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

=head1 NAME

SSL::Controller::sort - Catalyst Controller

=head1 DESCRIPTION

This 3 controler sort the list by name, key or result.

=head1 METHODS

=cut


sub sortName :GET Path('name/') {
    my ( $self, $c ) = @_;

    $c->stash->{menu} = $c->model('loadxml')->findType();
    $c->stash->{hashref} = $c->model('loadxml')->loadSortedType($c->request->path);
    $c->stash->{type} = $c->model('loadxml')->retType($c->request->path);
    $c->stash->{template} = 'index.tt2';
    $c->forward($c->view('HTML'));

}

sub sortKey :GET Path('key/') {
    my ( $self, $c ) = @_;

    $c->stash->{menu} = $c->model('loadxml')->findType();
    $c->stash->{hashref} = $c->model('loadxml')->loadSortedType($c->request->path);
    $c->stash->{type} = $c->model('loadxml')->retType($c->request->path);
    $c->stash->{template} = 'index.tt2';
    $c->forward($c->view('HTML'));

}

sub sortResult :GET Path('result/') {
    my ( $self, $c ) = @_;

    $c->stash->{menu} = $c->model('loadxml')->findType();
    $c->stash->{hashref} = $c->model('loadxml')->loadSortedType($c->request->path);
    $c->stash->{type} = $c->model('loadxml')->retType($c->request->path);
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


=encoding utf8

=head1 AUTHOR

Behar Ameti,

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;
