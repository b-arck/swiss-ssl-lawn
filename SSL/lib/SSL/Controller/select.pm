package SSL::Controller::select;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

=head1 NAME

SSL::Controller::select - Catalyst Controller

=head1 DESCRIPTION

This controller display the detail for an selected ID.

=head1 METHODS

=cut


=head2 index

=cut

sub details :GET Path('ID/') {
    my ( $self, $c ) = @_;

    $c->stash->{hashref} = $c->model('loadxml')->loadDetails($c->request->path);
    $c->stash->{ID} = $c->model('loadxml')->getId($c->request->path);
    $c->stash->{template} = 'details.tt2';
    $c->forward($c->view('HTML'));

}

sub graph :GET Path('/select/graph/') {
    my ( $self, $c ) = @_;

    $c->stash->{graphs} = $c->model('loadxml')->drawChart($c->request->path);
    $c->stash->{hname} = $c->model('loadxml')->getName($c->request->path);
    $c->stash->{template} = 'graph.tt2';
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


=head1 NAME

SSL::Controller::select - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller for all selection and index web page

=head1 METHODS

=cut


=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    $c->stash->{nav} = $c->model('loadxml')->findType();
    $c->stash->{hashref} = $c->model('loadxml')->loadAllData();
    $c->stash(type => 'all');
    $c->stash->{template} = 'index.tt2';
    $c->forward($c->view('HTML'));
}

sub selectType :GET Path('') {
    my ( $self, $c ) = @_;

    $c->stash->{nav} = $c->model('loadxml')->findType();
    $c->stash->{hashref} = $c->model('loadxml')->loadSiteByType($c->request->path);
    $c->stash->{type} = $c->model('loadxml')->retTypeSelect($c->request->path);
    $c->stash->{template} = 'index.tt2';
    $c->forward($c->view('HTML'));

}

=head2 end

Attempt to render a view, if needed.

=cut

sub end : ActionClass('RenderView') {}

=encoding utf8

=head1 AUTHOR

Behar Ameti

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;
