package Dancer::Plugin::Auth::Extensible::Provider::SIP2;

use base 'Dancer::Plugin::Auth::Extensible::Provider::Base';
use Dancer qw(:syntax);
use SIP2::SC;
use DateTime;
use Modern::Perl;

=head1 NAME

Dancer::Plugin::Auth::Extensible::Provider::SIP2 - The great new Dancer::Plugin::Auth::Extensible::Provider::SIP2!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Dancer::Plugin::Auth::Extensible::Provider::SIP2;

    my $foo = Dancer::Plugin::Auth::Extensible::Provider::SIP2->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS

=head2 authenticate_user

Given the username and password entered by the user, return true if they are
authenticated, or false if not.

=cut

sub authenticate_user {
    my ($self, $patron_username, $patron_password) = @_;
    
    my $settings = $self->realm_settings;
    debug "*** Authenticating against: " . $settings->{host};
    my $sc = SIP2::SC->new( $settings->{host} );
    
    # Attempt to log in to the SIP2 server
    my $username = $settings->{username};
    my $password = $settings->{password};
    my $login_reply = $sc->message("9300CN$username|CO$password|");
    $login_reply = _clean_sip2_reply( $login_reply );
    debug "*** Login: " . $login_reply;
    
    ## Send the Patron Status Request
    
    # Code for the message we want to send. 23 = Patron Status Request
    my $code = '23'; 
    # Language - 3 char, fixed lenght, required
    my $lang = '   '; 
    # Transaction date - 18 char, fixed length, required. Format: YYYYMMDDZZZZHHMMSS
    my $dt = DateTime->now;
    my $date = $dt->strftime("%Y%m%d    %H%M%S"); 
    # Institution ID - variable length, required field
    my $inst = 'AO|';
    # Patron identifier - variable length, required field
    my $patron = "AA$patron_username|";
    # Terminal password - variable length, required field
    my $term = "AC$password|";
    # Patron password - variable length, required field
    my $pass = "AD$patron_password|";
    
    my $msg = $code . $lang . $date . $inst . $patron . $term . $pass;
    debug "*** Message being sent: " . $msg;
    
    my $record = $sc->message( $msg );
    $record = _clean_sip2_reply( $record );
    debug "*** Response from SIP2 server:" . $record;
    
    return _sip2_indicates_valid_user( $record );    
    
}

=head2 get_user_details

Given a username, return details about the user. 

Details should be returned as a hashref.

=cut

sub get_user_details {
    my ($self, $patron_username) = @_;

    my $settings = $self->realm_settings;
    debug "*** Authenticating against: " . $settings->{host};
    my $sc = SIP2::SC->new( $settings->{host} );

    ## Send the Patron Information message
    
    # Code for the message we want to send. 63 = Patron Information
    my $code = '63'; 
    # Language - 3 char, fixed lenght, required
    my $lang = '   '; 
    # Transaction date - 18 char, fixed length, required. Format: YYYYMMDDZZZZHHMMSS
    my $dt = DateTime->now;
    my $date = $dt->strftime("%Y%m%d    %H%M%S"); 
    # Summary - 10 char, fixed lenght, required
    my $summary = '          ';
    # Institution ID - variable length, required field
    my $inst = 'AO|';
    # Patron identifier - variable length, required field
    my $patron = "AA$patron_username|";
    # Terminal password - variable length, required field
    my $term = "AC|";
    # Patron password - variable length, required field
    my $pass = "AD|";
    
    my $msg = $code . $lang . $date . $summary . $inst . $patron . $term . $pass;
    debug "*** Message being sent: " . $msg;
    
    my $record = $sc->message( $msg );
    $record = _clean_sip2_reply( $record );
    debug "*** Response from SIP2 server:" . $record;
    
    ## Parse the Patron Information Response we received from the server
    
    # BL - Check for a valid patron. BLY = valid, BLN = not valid
    if ( $record =~ m/\|BLN/ ) {
    
        debug "*** Authentication failed: not a valid patron";
        return;
    
    } elsif ( $record =~ m/\|BLY/ ) {
    
        my $user = {};
        
        # Email
        $record =~ m/\|BE(.*?)\|/;
        $user->{email} = $1;

        # Name
        $record =~ m/\|AE(.*?)\|/;
        $user->{name} = $1;
       
        return $user;
            
    } else {
    
        die "Response from SIP2 does not contain neither BLY nor BLN. This should not happen!";
    
    }
    
}

=head2 get_user_roles

Given a username, return a list of roles that user has.

=cut

sub get_user_roles {
    my @roles = ( 'sip2user' );
    return \@roles;
}

=head2 _clean_sip2_reply

Replies from SIP2 can contain weird chars that make them not show up in the logs.
This subroutine takes a raw SIP2 reply and tries to remove any offending chars. 

=cut

sub _clean_sip2_reply {

    my ( $s ) = @_;

    # Borrowed from Koha's C4::SIP::Sip
    $s =~ s/^\s*[^A-z0-9]+//s; # Every line must start with a "real" character.  Not whitespace, control chars, etc. 
    $s =~ s/[^A-z0-9]+$//s;    # Same for the end.  Note this catches the problem some clients have sending empty fields at the end, like |||
    $s =~ s/\015?\012//g;      # Extra line breaks must die
    $s =~ s/\015?\012//s;      # Extra line breaks must die
    $s =~ s/\015*\012*$//s;    # treat as one line to include the extra linebreaks we are trying to remove!
    
    return $s;

}

=head2 _sip2_indicates_valid_user

Checks a message from SIP2 for signs ov a valid user. The message should contain both "BLY" and "CQY". 

=cut

sub _sip2_indicates_valid_user {

    my ( $s ) = @_;

    # BL - Check for a valid patron. BLY = valid, BLN = not valid
    if ( $s =~ m/\|BLN/ ) {
    
        debug "*** Authentication failed: not a valid patron";
        return;
    
    } elsif ( $s =~ m/\|BLY/ ) {
    
        # CQ - Valid patron password. CQY = valid, CQN = not valid
        if ( $s =~ m/\|CQN/ ) {
        
            debug "*** Authentication failed: not a valid patron password";
            return;
        
        } elsif ( $s =~ m/\|CQY/ ) {
    
            return 1;
            
        } else {
        
            die "Message from SIP2 does not contain neither CQY nor CQN. This should not happen! $s";
        
        }
            
    } else {
    
        die "Message from SIP2 does not contain neither BLY nor BLN. This should not happen! $s";
    
    }
    
}

=head1 AUTHOR

Magnus Enger, C<< <magnus at enger.priv.no> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-dancer-plugin-auth-extensible-provider-sip2 at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Dancer-Plugin-Auth-Extensible-Provider-SIP2>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Dancer::Plugin::Auth::Extensible::Provider::SIP2


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Dancer-Plugin-Auth-Extensible-Provider-SIP2>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Dancer-Plugin-Auth-Extensible-Provider-SIP2>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Dancer-Plugin-Auth-Extensible-Provider-SIP2>

=item * Search CPAN

L<http://search.cpan.org/dist/Dancer-Plugin-Auth-Extensible-Provider-SIP2/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2013 Magnus Enger.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of Dancer::Plugin::Auth::Extensible::Provider::SIP2
