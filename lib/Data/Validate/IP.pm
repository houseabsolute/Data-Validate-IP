package Data::Validate::IP;

use strict;
use warnings;
use Net::Netmask;


require Exporter;

use constant LOOPBACK   => [qw(127.0.0.0/8)];
use constant TESTNET    => [qw(192.0.2.0/24)];
use constant PRIVATE    => [qw(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)];
use constant MULTICAST  => [qw(224.0.0.0/4)];
use constant LINKLOCAL  => [qw(169.254.0.0/16)];

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Data::Validate::IP ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

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
                is_linklocal_ipv6
);

our $VERSION = '0.14';

#Global, we store this only once
my %MASK;


# Preloaded methods go here.

# 

=head1 NAME

Data::Validate::IP - ipv4 and ipv6 validation methods

=head1 SYNOPSIS

  use Data::Validate::IP qw(is_ipv4 is_ipv6);
  
  if(is_ipv4($suspect)){
        print "Looks like an ipv4 address";
  } else {
        print "Not an ipv4 address\n";
  }

  if(is_ipv6($suspect)){
        print "Looks like an ipv6 address";
  } else {
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




sub new{
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

sub is_ipv4 {
        my $self = shift if ref($_[0]); 
        my $value = shift;
        
        return unless defined($value);
        
        my(@octets) = $value =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
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


sub is_ipv6 {
        my $self = shift if ref($_[0]); 
        my $value = shift;

        return unless defined($value);

	# if there is a :: then there must be only one ::
	# and the length can be variable
	# without it, the length must be 8 groups

	my (@chunks) = split(':', $value);
	#need to see if last chunk is an ipv4 address, if it is we pop it off and 
	#exempt it from the normal ipv6 checking and stick it back on at the end.
	#if only one chunk and it matches it isn't ipv6 - it is a ipv4 address only
	my $ipv4;
	my $expected_chunks = 8;
	if (@chunks > 1 && is_ipv4($chunks[$#chunks])) {
		$ipv4 = pop(@chunks);
		$expected_chunks--;
	}
	my $empty = 0;
	#Workaround to handle trailing :: being valid

	if ($value =~ /[0123456789abcdef]{1,4}::$/) {
		$empty++;
	} elsif ($value =~ /:$/) {
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
	} elsif ($empty > 1) {
		return;
	}

	if (defined $ipv4) {
		push(@chunks, $ipv4);
	}
	#Need 8 chunks, or we need an empty section that could be filled to represent the missing '0' sections
	return unless (@chunks == $expected_chunks || @chunks < $expected_chunks && $empty);

       	my $return = join(':', @chunks);
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
        my $self = shift if ref($_[0]); 
        my $value = shift;
        my $network = shift;
        
        return unless defined($value);

	my $ip = is_ipv4($value);
	return unless defined $ip;

	return unless Net::Netmask::findNetblock($ip,_mask($network));
	return $ip;
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

=item I<From RFC 3330>

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

=cut


sub is_private_ipv4 {
        my $self = shift if ref($_[0]); 
        my $value = shift;
        
        return unless defined($value);

	my $ip = is_ipv4($value);
	return unless defined $ip;

	return unless Net::Netmask::findNetblock($ip,_mask('private'));
	return $ip;
}

=pod

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

=item I<From RFC 3330>

   127.0.0.0/8 - This block is assigned for use as the Internet host
   loopback address.  A datagram sent by a higher level protocol to an
   address anywhere within this block should loop back inside the host.
   This is ordinarily implemented using only 127.0.0.1/32 for loopback,
   but no addresses within this block should ever appear on any network
   anywhere [RFC1700, page 5].

=back

=cut


sub is_loopback_ipv4 {
        my $self = shift if ref($_[0]); 
        my $value = shift;
        
        return unless defined($value);

	my $ip = is_ipv4($value);
	return unless defined $ip;

	return unless Net::Netmask::findNetblock($ip,_mask('loopback'));
	return $ip;
}

=pod

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

=item I<From RFC 3330>

   192.0.2.0/24 - This block is assigned as "TEST-NET" for use in
   documentation and example code.  It is often used in conjunction with
   domain names example.com or example.net in vendor and protocol
   documentation.  Addresses within this block should not appear on the
   public Internet.

=back

=cut


sub is_testnet_ipv4 {
        my $self = shift if ref($_[0]); 
        my $value = shift;
        
        return unless defined($value);

	my $ip = is_ipv4($value);
	return unless defined $ip;

	return unless Net::Netmask::findNetblock($ip,_mask('testnet'));
	return $ip;
}

=pod

=item B<is_multicast_ipv4> - is it a valid multicast ipv4 address

  is_multicast_ipv4($value);
  or
  $obj->is_multicast_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip addres if the test value appears to be a well-formed
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

=item I<From RFC 3330>

   224.0.0.0/4 - This block, formerly known as the Class D address
   space, is allocated for use in IPv4 multicast address assignments.
   The IANA guidelines for assignments from this space are described in
   [RFC3171].

=back

=cut


sub is_multicast_ipv4 {
       my $self = shift if ref($_[0]); 
       my $value = shift;

       return unless defined($value);

       my $ip = is_ipv4($value);
       return unless defined $ip;

       return unless Net::Netmask::findNetblock($ip,_mask('multicast'));
       return $ip;
}


=pod

=item B<is_linklocal_ipv4> - is it a valid link-local ipv4 address

  is_linklocal_ipv4($value);
  or
  $obj->is_linklocal_ipv4($value);

=over 4

=item I<Description>

Returns the untainted ip addres if the test value appears to be a well-formed
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

=item I<From RFC 3330>

   169.254.0.0/16 - This is the "link local" block.  It is allocated for
   communication between hosts on a single link.  Hosts obtain these
   addresses by auto-configuration, such as when a DHCP server may not
   be found.

=back

=cut


sub is_linklocal_ipv4 {
       my $self = shift if ref($_[0]); 
       my $value = shift;

       return unless defined($value);

       my $ip = is_ipv4($value);
       return unless defined $ip;

       return unless Net::Netmask::findNetblock($ip,_mask('linklocal'));
       return $ip;
}

=pod

=item B<is_linklocal_ipv6> - is it a valid link-local ipv6 address

  is_linklocal_ipv6($value);
  or
  $obj->is_linklocal_ipv6($value);

=over 4

=item I<Description>

Returns the untainted ip addres if the test value appears to be a well-formed
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

=item I<From RFC 2462>

   A link-local address is formed by prepending the well-known link-
   local prefix FE80::0 [ADDR-ARCH] (of appropriate length) to the
   interface identifier. If the interface identifier has a length of N
   bits, the interface identifier replaces the right-most N zero bits of
   the link-local prefix.  If the interface identifier is more than 118
   bits in length, autoconfiguration fails and manual configuration is
   required. Note that interface identifiers will typically be 64-bits
   long and based on EUI-64 identifiers as described in [ADDR-ARCH].

=back

=cut


sub is_linklocal_ipv6 {
       my $self = shift if ref($_[0]); 
       my $value = shift;

       return unless defined($value);

       my $ip = is_ipv6($value);
       return unless defined $ip;

       return unless $ip =~ /^fe80:/i;
       return $ip;
}





=pod

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


sub is_public_ipv4 {
        my $self = shift if ref($_[0]); 
        my $value = shift;
        
        return unless defined($value);

	my $ip = is_ipv4($value);
	return unless defined $ip;

	#Logic for this is inverted... all values from mask are 'not public'
	return if Net::Netmask::findNetblock($ip,_mask('public'));
	return $ip;
}




#We only want to bother building this once for each type
#We store it globally as it is effectively a constant
sub _mask {
	my $type = (shift);
	return $MASK{$type} if (defined $MASK{$type});
	my @masks;
	if ($type eq 'public') {
		@masks = (LOOPBACK, TESTNET, PRIVATE,MULTICAST,LINKLOCAL);
	} elsif ($type eq 'loopback') {
		@masks = (LOOPBACK);
	} elsif ($type eq 'private') {
		@masks = (PRIVATE);
	} elsif ($type eq 'testnet') {
		@masks = (TESTNET);
	} elsif ($type eq 'multicast') {
		@masks = (MULTICAST);
	} elsif ($type eq 'linklocal') {
		@masks = (LINKLOCAL);
	} else {
		@masks = ([$type]);
	}

	my $mask = {};
	foreach my $default (@masks) {
		foreach my $range (@{$default}) {
			my $block = Net::Netmask->new($range);
			$block->storeNetblock($mask);
		}   
	}   
	$MASK{$type}= $mask;
	return $MASK{$type};
}


1;
__END__


# -------------------------------------------------------------------------------

=back

=head1 SEE ALSO

IPv4

b<[RFC 3330] [RFC 1918] [RFC 1700]>

IPv6

b<[RFC 2460] [RFC 4291] [RFC 4294]>

=over 4

=item  L<Data::Validate(3)>

=item  L<Net::Netmask(3)>

=back

=head1 IPv6

IPv6 Support is new, please test it thoroughly and report any bugs.

=head1 AUTHOR

Neil Neely <F<neil@neely.cx>>.

=head1 ACKNOWLEDGEMENTS 

Thanks to Richard Sonnen <F<sonnen@richardsonnen.com>> for writing the Data::Validate module.

Thanks to Matt Dainty <F<matt@bodgit-n-scarper.com>> for adding the is_multicast_ipv4 and is_linklocal_ipv4 code.

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2010 Neil Neely.  




This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
