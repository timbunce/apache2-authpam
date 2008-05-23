package Apache2::AuthPAM;

=head1 NAME

Apache::AuthPAM - Authenticate apache request using PAM services

=cut

use 5.006;
use strict;
use warnings;

use Apache2::Const qw/:common/;
use Apache2::Log;

use Authen::PAM qw/pam_start pam_end pam_authenticate pam_acct_mgmt PAM_SUCCESS/;

our $VERSION = '0.01';

our $MODNAME = __PACKAGE__;

#
# I use this global to pass user info to the conversation function
#   if you know a better way to do it, please tell me and/or fix it.
#
our %pw;

# Preloaded methods go here.

sub handler {
  # get object request
  my $r = shift;

  # check first request
  return OK unless $r->is_initial_req;

  # get user password
  my ($rc, $pw) = $r->get_basic_auth_pw;

  # decline if not basic
  return $rc if $rc;

  # get log object
  my $log = $r->log;

  # get user name
  my $username = $r->user;

  # avoid blank username
  unless($username) {
    $r->note_basic_auth_failure;
    $log->info("$MODNAME: no user name supplied", $r->uri);
    return AUTH_REQUIRED;
  }

  # load apache config vars
  my $service = $r->dir_config('PAMservice');
  unless($service) {
    $log->alert("$MODNAME: no PAM service name supplied", $r->uri);
    return SERVER_ERROR;
  }

  # DAMN! I shouldn't use globals this way!
  $pw{$$}=$pw;

  # start PAM dialog
  my $pamh;
  my $result = pam_start($service, $username, \&my_conv_func, $pamh);

  unless ($result == PAM_SUCCESS) {
    $r->note_basic_auth_failure;
    $log->crit("$MODNAME: <$service> not started ($result) ", $r->uri);
    pam_end($pamh, 0);
    return SERVER_ERROR;
  }

  $result = pam_authenticate($pamh, 0);
  unless ($result == PAM_SUCCESS) {
    $r->note_basic_auth_failure;
    $log->info("$MODNAME: <$username> not authenticated by $service ($result) ", $r->uri);
    pam_end($pamh, 0);
    return AUTH_REQUIRED;
  }

  $result = pam_acct_mgmt($pamh, 0);
  unless ($result == PAM_SUCCESS) {
    $r->note_basic_auth_failure;
    $log->info("$MODNAME: <$username> no acct mgmt by $service ($result) ", $r->uri);
    pam_end($pamh, 0);
    return AUTH_REQUIRED;
  }

  # Authenticated
  pam_end($pamh, 0);
  $log->info("$MODNAME: <$username> authenticated by $service", $r->uri);

  return OK;
}


#
# Conversation Function
#
sub my_conv_func {
  my @res;
  while(@_) {
    my $msg_type = shift;
    my $msg = shift;
    push @res, (0, $pw{$$});
  }
  push @res, 0;
  return @res;
}

1;
__END__

=head1 SYNOPSIS

  # /etc/httpd.conf
  <Directory /var/www/https/secured-area/>
     AuthType Basic
     AuthName "your server account"
     PerlAuthHandler Apache2::AuthPAM
     PerlSetVar PAMservice check_user
     require valid-user
  </Directory>

  # /etc/pam.d/check_user
  #%PAM-1.0
  auth        required    /lib/security/pam_pwdb.so nodelay
  account     required    /lib/security/pam_pwdb.so

=head1 DESCRIPTION

This perl module is designed to work with mod_perl and the
Authen::PAM module.

You can select the PAM service setting the perl var PAMservice

  PerlSetVar PAMservice the-pam-service-you-want

You can select different PAM services for different directories
or locations in your web server filesystem space.

Apache2::AuthPAM works as follows:

First, it calls C<pam_start> with the selected service.
Second, it calls C<pam_authenticate> with the browser/apache supplied username and password.
Later, it calls C<pam_acct_mgmt>.
And finally it calls C<pam_end>.
If any of the PAM functions fail, Apache2::AuthPAM logs an info level message and returns C<AUTH_REQUIRED>.
If all PAM functions are succesfull, Apache2::AuthPAM logs an info level message and returns C<OK>.

Remember that if you don't use https (SSL) then your username and password is
transmitted on the network in plain text with each request. So if you are going
to use your system password database, you B<MUST> also use B<mod_ssl> or you
accounts will be easily compromised.

=head1 BUGS

I'am using a global symbol.

Apache2::AuthPAM is running as the same user mod_perl is running
(on RedHat Linux it is apache). It is running without privileges.

=head1 AUTHOR

Tim Bunce L<http://www.tim.bunce.name> based on work by Héctor Daniel Cortés González E<lt>hdcg@cie.unam.mxE<gt>

=head1 CREDITS

Apache2::AuthPAM is a direct adaptation of Héctor Daniel Cortés González's
Apache::AuthPAM which was itself a direct adaptation of Demetrios E. Paneras'
E<lt>dep@media.mit.eduE<gt> Apache::AuthenNISplus. 
Authen::PAM is written by Nikolay Pelov E<lt>nikip@iname.comE<gt>.
The sample PAM application check_user.c was contribuited by Shane Watts 
with modifications by AGM.

=head1 COPYRIGHT

This apache perl module is Free Software, and can be used under 
the terms of the GNU General Public License v2.0 or later.

=head1 SEE ALSO

L<perl>, L<mod_perl>, L<mod_ssl>, L<Authen::PAM>, L<Linux-PAM>

=cut
