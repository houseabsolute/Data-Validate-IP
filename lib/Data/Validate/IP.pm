package Data::Validate::IP;

use strict;
use warnings;

use NetAddr::IP 4;
use Scalar::Util qw( blessed );

require Exporter;

our $HAS_SOCKET;

BEGIN {
    $HAS_SOCKET = (!$ENV{DVI_NO_SOCKET})
        && eval {
        require Socket;
        Socket->import(qw( AF_INET AF_INET6 inet_pton ));
        # On some platforms, Socket.pm exports an inet_pton that just dies
        # when it is called. On others, inet_pton accepts various forms of
        # invalid input.
        defined &Socket::inet_pton
            && !defined inet_pton(Socket::AF_INET(),  '016.17.184.1')
            && !defined inet_pton(Socket::AF_INET6(), '2067::1:');
        };

    if ($HAS_SOCKET) {
        *is_ipv4 = \&_fast_is_ipv4;
        *is_ipv6 = \&_fast_is_ipv6;
    }
    else {
        *is_ipv4 = \&_slow_is_ipv4;
        *is_ipv6 = \&_slow_is_ipv6;
    }
}

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Data::Validate::IP ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = (
    'all' => [
        qw(

            )
    ]
);

our @EXPORT_OK = (@{ $EXPORT_TAGS{'all'} });

our @EXPORT = qw(
    is_ipv4
    is_ipv6

    is_innet_ipv4
    is_private_ipv4
    is_loopback_ipv4
    is_testnet_ipv4
    is_public_ipv4
    is_multicast_ipv4
    is_linklocal_ipv4
    is_unroutable_ipv4

    is_private_ipv6
    is_loopback_ipv6
    is_public_ipv6
    is_multicast_ipv6
    is_linklocal_ipv6
    is_special_ipv6
);

our $VERSION = '0.14';

#Global, we store this only once

# ABSTRACT: ipv4 and ipv6 validation methods

=head1 SYNOPSIS

  use Data::Validate::IP qw(is_ipv4 is_ipv6);

  if (is_ipv4($suspect)) {
      print "Looks like an ipv4 address";
  }
  else {
      print "Not an ipv4 address\n";
  }

  if (is_ipv6($suspect)) {
      print "Looks like an ipv6 address";
  }
  else {
      print "Not an ipv6 address\n";
  }

  # or as an object
  my $v = Data::Validate::IP->new();

  die "not an ipv4 ip" unless ($v->is_ipv4('domain.com'));

  die "not an ipv6 ip" unless ($v->is_ipv6('domain.com'));

=head1 DESCRIPTION

This module collects ip validation routines to make input validation,
and untainting easier and more readable.

All functions return an untainted value if the test passes, and undef if
it fails.  This means that you should always check for a defined status explicitly.
Don't assume the return will be true. (e.g. is_username('0'))

The value to test is always the first (and often only) argument.

All of the functions below are exported by default.

=head1 FUNCTIONS

=over 4


=item B<new> - constructor for OO usage

  $obj = Data::Validate::IP->new();

=over 4

=item I<Description>

Returns a Data::Validator::IP object.  This lets you access all the validator function
calls as methods without importing them into your namespace or using the clumsy
Data::Validate::IP::function_name() format.

=item I<Arguments>

None

=item I<Returns>

Returns a Data::Validate::IP object

=back

=cut

sub new {
    my $class = shift;

    return bless {}, $class;
}

# -------------------------------------------------------------------------------

=pod

=item B<is_ipv4> - does the value look like an ip v4 address?

  is_ipv4($value);
  or
  $obj->is_ipv4($value);


=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists. It only looks to see that the format is appropriate.

=back

=cut

sub _fast_is_ipv4 {
    shift if ref $_[0];
    my $value = shift;

    return
        unless defined $value && defined inet_pton(Socket::AF_INET(), $value);

    $value =~ /(.+)/;
    return $1;
}

sub _slow_is_ipv4 {
    shift if ref $_[0];
    my $value = shift;

    return unless defined($value);

    my (@octets) = $value =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    return unless (@octets == 4);
    foreach (@octets) {

        #return unless ($_ >= 0 && $_ <= 255);
        return unless ($_ >= 0 && $_ <= 255 && $_ !~ /^0\d{1,2}$/);
    }

    return join('.', @octets);
}

# -------------------------------------------------------------------------------
#

=pod

=item B<is_ipv6> - does the value look like an ip v6 address?

  is_ipv6($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists. It only looks to see that the format is appropriate.

=back

=cut

sub _fast_is_ipv6 {
    shift if ref $_[0];
    my $value = shift;

    return
        unless defined $value
        && defined inet_pton(Socket::AF_INET6(), $value);

    $value =~ /(.+)/;
    return $1;
}

sub _slow_is_ipv6 {
    shift if ref $_[0];
    my $value = shift;

    return unless defined($value);

    # This is valid but the algorithm below won't do the right thing with it.
    return '::' if $value eq '::';

    # if there is a :: then there must be only one ::
    # and the length can be variable
    # without it, the length must be 8 groups

    my (@chunks) = split(':', $value);

    #need to see if last chunk is an ipv4 address, if it is we pop it off and
    #exempt it from the normal ipv6 checking and stick it back on at the end.
    #if only one chunk and it matches it isn't ipv6 - it is a ipv4 address only
    my $ipv4;
    my $expected_chunks = 8;
    if (@chunks > 1 && is_ipv4($chunks[-1])) {
        $ipv4 = pop(@chunks);
        $expected_chunks--;
    }
    my $empty = 0;

    #Workaround to handle trailing :: being valid

    if ($value =~ /[0123456789abcdef]{1,4}::$/) {
        $empty++;
    }
    elsif ($value =~ /:$/) {

        #single trailing ':' is invalid
        return;
    }
    foreach (@chunks) {
        return unless (/^[0123456789abcdef]{0,4}$/i);
        $empty++ if /^$/;
    }

    #More than one :: block is bad, but if it starts with :: it will look like two, so we need an exception.
    if ($empty == 2 && $value =~ /^::/) {

        #This is ok
    }
    elsif ($empty > 1) {
        return;
    }

    if (defined $ipv4) {
        push(@chunks, $ipv4);
    }

    #Need 8 chunks, or we need an empty section that could be filled to represent the missing '0' sections
    return
        unless (@chunks == $expected_chunks
        || @chunks < $expected_chunks && $empty);

    my $return = join(':', @chunks);

    #Explicitly untaint the data
    $return =~ /(.+)/;
    $return = $1;

    #Need to handle the exception of trailing :: being valid
    return $return . '::' if ($value =~ /::$/);
    return $return;

}

=pod

=item B<is_innet_ipv4> - is it a valid ipv4 address in the network specified

  is_innet_ipv4($value,$network);
  or
  $obj->is_innet_ipv4($value,$network);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
ip address inside of the network specified

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=item $network

The potential network the IP must be a part of. Functionality uses Net::Netmask and should be in the form:

       '216.240.32.0/24'               The preferred form.

       '216.240.32.0:255.255.255.0'
       '216.240.32.0-255.255.255.0'
       '216.240.32.0 - 216.240.32.255'
       '216.240.32.4'                  A /32 block.

       '216.240.32'                    Always a /24 block.

       '216.240'                       Always a /16 block.

       '140'                           Always a /8 block.

       '216.240.32/24'
       '216.240/16'
       'default'                       0.0.0.0/0 (the default route)

       '216.240.32.0#0.0.31.255'       A hostmask (as used by Cisco
                                       access-lists).

Examples taken from Net::Netmask documentation.  For more advanced network matching needs please see Net::Netmask.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=back

=cut

sub is_innet_ipv4 {
    shift if ref $_[0];
    my $value   = shift;
    my $network = shift;

    return unless defined($value);

    my $ip = is_ipv4($value);
    return unless defined $ip;

    $network = NetAddr::IP->new($network) or return;
    my $netaddr_ip = NetAddr::IP->new($ip) or return;

    return $ip if $network->contains($netaddr_ip);
    return;
}

=pod

=item B<is_private_ipv4> - is it a valid private ipv4 address

  is_private_ipv4($value);
  or
  $obj->is_private_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
private ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 5735>

   10.0.0.0/8 - This block is set aside for use in private networks.
   Its intended use is documented in [RFC1918].  Addresses within this
   block should not appear on the public Internet.

   172.16.0.0/12 - This block is set aside for use in private networks.
   Its intended use is documented in [RFC1918].  Addresses within this
   block should not appear on the public Internet.

   192.168.0.0/16 - This block is set aside for use in private networks.
   Its intended use is documented in [RFC1918].  Addresses within this
   block should not appear on the public Internet.


=back

=item B<is_loopback_ipv4> - is it a valid loopback ipv4 address

  is_loopback_ipv4($value);
  or
  $obj->is_loopback_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
loopback ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 5735>

   127.0.0.0/8 - This block is assigned for use as the Internet host
   loopback address.  A datagram sent by a higher level protocol to an
   address anywhere within this block should loop back inside the host.
   This is ordinarily implemented using only 127.0.0.1/32 for loopback,
   but no addresses within this block should ever appear on any network
   anywhere [RFC1700, page 5].

=back

=item B<is_testnet_ipv4> - is it a valid testnet ipv4 address

  is_testnet_ipv4($value);
  or
  $obj->is_testnet_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
testnet ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 5735>

   192.0.2.0/24 - This block is assigned as "TEST-NET" for use in
   documentation and example code.  It is often used in conjunction with
   domain names example.com or example.net in vendor and protocol
   documentation.  Addresses within this block should not appear on the
   public Internet.

=back

=item B<is_multicast_ipv4> - is it a valid multicast ipv4 address

  is_multicast_ipv4($value);
  or
  $obj->is_multicast_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
multicast ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 5735>

   224.0.0.0/4 - This block, formerly known as the Class D address
   space, is allocated for use in IPv4 multicast address assignments.
   The IANA guidelines for assignments from this space are described in
   [RFC3171].

=back

=item B<is_linklocal_ipv4> - is it a valid link-local ipv4 address

  is_linklocal_ipv4($value);
  or
  $obj->is_linklocal_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
link-local ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 5735>

   169.254.0.0/16 - This is the "link local" block.  It is allocated for
   communication between hosts on a single link.  Hosts obtain these
   addresses by auto-configuration, such as when a DHCP server may not
   be found.

=back

=item B<is_unroutable_ipv4> - is it a valid unroutable ipv4 address

  is_unroutable_ipv4($value);
  or
  $obj->is_unroutable_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
unroutable ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 5375>

   0.0.0.0/8 - Addresses in this block refer to source hosts on "this"
   network.  Address 0.0.0.0/32 may be used as a source address for this
   host on this network; other addresses within 0.0.0.0/8 may be used to
   refer to specified hosts on this network ([RFC1122], Section
   3.2.1.3).

   192.0.0.0/24 - This block is reserved for IETF protocol assignments.
   At the time of writing this document, there are no current
   assignments.  Allocation policy for future assignments is given in
   [RFC5736].

   198.18.0.0/15 - This block has been allocated for use in benchmark
   tests of network interconnect devices.  [RFC2544] explains that this
   range was assigned to minimize the chance of conflict in case a
   testing device were to be accidentally connected to part of the
   Internet.  Packets with source addresses from this range are not
   meant to be forwarded across the Internet.

   198.51.100.0/24 - This block is assigned as "TEST-NET-2" for use in
   documentation and example code.  It is often used in conjunction with
   domain names example.com or example.net in vendor and protocol
   documentation.  As described in [RFC5737], addresses within this
   block do not legitimately appear on the public Internet and can be
   used without any coordination with IANA or an Internet registry.

   203.0.113.0/24 - This block is assigned as "TEST-NET-3" for use in
   documentation and example code.  It is often used in conjunction with
   domain names example.com or example.net in vendor and protocol
   documentation.  As described in [RFC5737], addresses within this
   block do not legitimately appear on the public Internet and can be
   used without any coordination with IANA or an Internet registry.

   240.0.0.0/4 - This block, formerly known as the Class E address
   space, is reserved for future use; see [RFC1112], Section 4.

=back

=item B<is_public_ipv4> - is it a valid public ipv4 address

  is_public_ipv4($value);
  or
  $obj->is_public_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
public ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists or could truly route.  This is true for any
non- private/testnet/loopback ip.

=back

=cut

{
    my %ipv4_networks = (
        loopback => [qw(127.0.0.0/8)],
        private  => [
            qw(
                10.0.0.0/8
                172.16.0.0/12
                192.168.0.0/16
                )
        ],
        testnet    => [qw(192.0.2.0/24)],
        multicast  => [qw(224.0.0.0/4)],
        linklocal  => [qw(169.254.0.0/16)],
        unroutable => [
            qw(
                0.0.0.0/8
                100.64.0.0/10
                192.0.0.0/29
                198.18.0.0/15
                198.51.100.0/24
                203.0.113.0/24
                240.0.0.0/4
                )
        ],
    );

    _build_is_X_ip_subs(\%ipv4_networks, 4);
}

=pod

=item B<is_private_ipv6> - is it a valid private ipv6 address

  is_private_ipv6($value);
  or
  $obj->is_private_ipv6($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
private ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 4193>

   The default behavior of exterior routing protocol sessions between
   administrative routing regions must be to ignore receipt of and not
   advertise prefixes in the FC00::/7 block.  A network operator may
   specifically configure prefixes longer than FC00::/7 for inter-site
   communication.

=back

=item B<is_loopback_ipv6> - is it a valid loopback ipv6 address

  is_loopback_ipv6($value);
  or
  $obj->is_loopback_ipv6($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
loopback ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 4291>

   The unicast address 0:0:0:0:0:0:0:1 is called the loopback address.
   It may be used by a node to send an IPv6 packet to itself.  It must
   not be assigned to any physical interface.  It is treated as having
   Link-Local scope, and may be thought of as the Link-Local unicast
   address of a virtual interface (typically called the "loopback
   interface") to an imaginary link that goes nowhere.

=back

=item B<is_multicast_ipv6> - is it a valid multicast ipv6 address

  is_multicast_ipv6($value);
  or
  $obj->is_multicast_ipv6($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
multicast ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 4291>

   An IPv6 multicast address is an identifier for a group of interfaces
   (typically on different nodes).  An interface may belong to any
   number of multicast groups.  Multicast addresses have the following
   format:

   |   8    |  4 |  4 |                  112 bits                   |
   +------ -+----+----+---------------------------------------------+
   |11111111|flgs|scop|                  group ID                   |
   +--------+----+----+---------------------------------------------+

=back

=item B<is_linklocal_ipv6> - is it a valid link-local ipv6 address

  is_linklocal_ipv6($value);
  or
  $obj->is_linklocal_ipv6($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
link-local ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 4291>

   Link-Local addresses are for use on a single link.  Link-Local
   addresses have the following format:

   |   10     |
   |  bits    |         54 bits         |          64 bits           |
   +----------+-------------------------+----------------------------+
   |1111111010|           0             |       interface ID         |
   +----------+-------------------------+----------------------------+

   Link-Local addresses are designed to be used for addressing on a
   single link for purposes such as automatic address configuration,
   neighbor discovery, or when no routers are present.

=back

=item B<is_special_ipv6> - is it a valid special purpose ipv6 address

  is_special_ipv6($value);
  or
  $obj->is_special_ipv6($value);

=over 4

=item I<Description>

Returns the untainted ip address if the test value appears to be a well-formed
special purpose ip address.

=item I<Arguments>

=over 4

=item $value

The potential ip to test.

=back

=item I<Returns>

Returns the untainted ip on success, undef on failure.

=item I<Notes, Exceptions, & Bugs>

The function does not make any attempt to check whether an ip
actually exists.

=item I<From RFC 2928>

   The block of Sub-TLA IDs assigned to the IANA (i.e., 2001:0000::/29 -
   2001:01F8::/29) is for assignment for testing and experimental usage
   to support activities such as the 6bone, and for new approaches like
   exchanges.

=back

The whole block of special IPv6 addresses can be written simple as 2001::/23.

=cut

{
    my %ipv6_networks = (
        loopback  => '::1/128',
        private   => 'fc00::/7',
        multicast => 'ff00::/8',
        linklocal => 'fe80::/10',
        special   => '2001::/23',
    );

    _build_is_X_ip_subs(\%ipv6_networks, 6);
}

sub _build_is_X_ip_subs {
    my $networks  = shift;
    my $ip_number = shift;

    my $is_ip_sub   = $ip_number == 4 ? 'is_ipv4' : 'is_ipv6';
    my $netaddr_new = $ip_number == 4 ? 'new'     : 'new6';

    my @all_nets;

    local $@;
    for my $type (keys %{$networks}) {
        my @nets
            = map { NetAddr::IP->$netaddr_new($_) }
            ref $networks->{$type}
            ? @{ $networks->{$type} }
            : $networks->{$type};

        push @all_nets, @nets;

        # We're using code gen rather than just making an anon sub outright so
        # we don't have to pay the cost of derefencing the $is_ip_sub and the
        # dynamic dispatch cost for $netaddr_new
        my $sub = eval sprintf( <<'EOF', $is_ip_sub, $netaddr_new );
sub {
    shift if ref $_[0];
    my $value = shift;

    return unless defined $value;

    my $ip = %s($value);
    return unless defined $ip;

    my $netaddr_ip = NetAddr::IP->%s($ip);
    for my $net (@nets) {
        return $ip if $net->contains($netaddr_ip);
    }
    return;
}
EOF
        die $@ if $@;

        my $sub_name = 'is_' . $type . '_ipv' . $ip_number;
        no strict 'refs';
        *{$sub_name} = $sub;
    }

    my $sub = eval sprintf( <<'EOF', $is_ip_sub, $netaddr_new );
sub {
    shift if ref $_[0];
    my $value = shift;

    return unless defined($value);

    my $ip = %s($value);
    return unless defined $ip;

    my $netaddr_ip = NetAddr::IP->%s($ip);
    for my $net (@all_nets) {
        return if $net->contains($netaddr_ip);
    }

    return $ip;
}
EOF
    die $@ if $@;

    my $sub_name = 'is_public_ipv' . $ip_number;
    no strict 'refs';
    *{$sub_name} = $sub;
}

1;
__END__


# -------------------------------------------------------------------------------

=back

=head1 SEE ALSO

IPv4

B<[RFC 5735] [RFC 1918]>

IPv6

B<[RFC 2460] [RFC 4193] [RFC 4291] [RFC 6434]>

=over 4

=item  L<Data::Validate(3)>

=item  L<Net::Netmask(3)>

=back

=head1 IPv6

IPv6 Support is new, please test it thoroughly and report any bugs.

=head1 ACKNOWLEDGEMENTS

Thanks to Richard Sonnen <F<sonnen@richardsonnen.com>> for writing the Data::Validate module.

Thanks to Matt Dainty <F<matt@bodgit-n-scarper.com>> for adding the is_multicast_ipv4 and is_linklocal_ipv4 code.

=cut
