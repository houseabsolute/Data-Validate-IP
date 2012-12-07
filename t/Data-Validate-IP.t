# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Data-Validate-IP.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 50;
BEGIN { use_ok('Data::Validate::IP', qw(is_ipv4 is_innet_ipv4 is_ipv6 is_private_ipv4 is_loopback_ipv4 is_testnet_ipv4 is_public_ipv4 is_multicast_ipv4 is_linklocal_ipv4 is_linklocal_ipv6)) }

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

is(is_ipv4('216.17.184.1'),  '216.17.184.1', 'is_ipv4 216.17.184.1');
is(is_ipv4('0.0.0.0'),       '0.0.0.0',      'is_ipv4 0.0.0.0');
is(is_ipv4('www.neely.cx'),  undef,          'is_ipv4 www.neely.cx');
is(is_ipv4('216.17.184.G'),  undef,          'is_ipv4 216.17.184.G');
is(is_ipv4('216.17.184.1.'), undef,          'is_ipv4 216.17.184.1.');
is(is_ipv4('216.17.184'),    undef,          'is_ipv4 216.17.184');
is(is_ipv4('216.17.184.'),   undef,          'is_ipv4 216.17.184.');
is(is_ipv4('256.17.184.1'),  undef,          'is_ipv4 256.17.184.1');
is(is_ipv4('216.017.184.1'), undef,          'is_ipv4 216.017.184.1');
is(is_ipv4('016.17.184.1'),  undef,          'is_ipv4 016.17.184.1');

is(is_innet_ipv4('216.17.184.1', '216.17.184.0/24'), '216.17.184.1', 'is_innet_ipv4 216.17.184.1 216.17.184.0/24');
is(is_innet_ipv4('127.0.0.1', '216.17.184.0/24'), undef, 'is_innet_ipv4 127.0.0.1 216.17.184.0/24');

is(is_private_ipv4('10.0.0.1'),   '10.0.0.1',   'is_private_ipv4 10.0.0.1');
is(is_private_ipv4('172.16.0.1'), '172.16.0.1', 'is_private_ipv4 172.16.0.1');
is(is_private_ipv4('192.168.0.1'), '192.168.0.1', 'is_private_ipv4 192.168.0.1');
is(is_private_ipv4('216.17.184.1'), undef, 'is_private_ipv4 216.17.184.1');

is(is_loopback_ipv4('127.0.0.1'), '127.0.0.1', 'is_loopback_ipv4 127.0.0.1');
is(is_testnet_ipv4('192.0.2.9'),  '192.0.2.9', 'is_testnet_ipv4 192.0.2.9');

is(is_public_ipv4('216.17.184.1'), '216.17.184.1', 'is_public_ipv4 216.17.184.1');
is(is_public_ipv4('192.168.0.1'), undef, 'is_public_ipv4 192.168.0.1');

is(is_multicast_ipv4('224.0.0.1'), '224.0.0.1', 'is_multicast_ipv4 224.0.0.1');
is(is_multicast_ipv4('216.17.184.1'), undef, 'is_multicast_ipv4 216.17.184.1');

is(is_public_ipv4('169.254.0.1'), undef, 'is_public_ipv4 169.254.0.1');
is(is_public_ipv4('224.0.0.1'),   undef, 'is_public_ipv4 224.0.0.1');

is(is_linklocal_ipv4('169.254.0.1'), '169.254.0.1', 'is_linklocal_ipv4 169.254.0.1');
is(is_linklocal_ipv4('216.17.184.1'), undef, 'is_linklocal_ipv4 216.17.184.1');

is(is_ipv6('2067:fa88'),    undef,          'is_ipv6 2067:fa88');
is(is_ipv6('2067:FA88'),    undef,          'is_ipv6 2067:FA88');
is(is_ipv6('2067:fa88::0'), '2067:fa88::0', 'is_ipv6 2067:fa88::0');
is(is_ipv6('2067:FA88::1'), '2067:FA88::1', 'is_ipv6 2067:FA88::1');
is(is_ipv6('2607:fa88::8a2e:370:7334'), '2607:fa88::8a2e:370:7334', 'is_ipv6 2607:fa88::8a2e:370:7334');
is(is_ipv6('2001:0db8:0000:0000:0000:0000:1428:57ab'), '2001:0db8:0000:0000:0000:0000:1428:57ab', 'is_ipv6 2001:0db8:0000:0000:0000:0000:1428:57ab');
is(is_ipv6('2001:0db8:0000:0000:0000::1428:57ab'), '2001:0db8:0000:0000:0000::1428:57ab', 'is_ipv6 2001:0db8:0000:0000:0000::1428:57ab');
is(is_ipv6('2001:0db8:0:0:0:0:1428:57ab'), '2001:0db8:0:0:0:0:1428:57ab', 'is_ipv6 2001:0db8:0:0:0:0:1428:57ab');
is(is_ipv6('2001:0db8:0:0::1428:57ab'), '2001:0db8:0:0::1428:57ab', 'is_ipv6 2001:0db8:0:0::1428:57ab');
is(is_ipv6('2001:0db8::1428:57ab'), '2001:0db8::1428:57ab', 'is_ipv6 2001:0db8::1428:57ab');
is(is_ipv6('2001:db8::1428:57ab'), '2001:db8::1428:57ab', 'is_ipv6 2001:db8::1428:57ab');
is(is_ipv6('::0'), '::0', 'is_ipv6 ::0');
is(is_ipv6('::1'), '::1', 'is_ipv6 ::1');

is(is_ipv6('::ffff:12.34.56.78'), '::ffff:12.34.56.78', 'is_ipv6 ::ffff:12.34.56.78');
is(is_ipv6('0:0:0:0:0:ffff:12.34.56.78'), '0:0:0:0:0:ffff:12.34.56.78', 'is_ipv6 0:0:0:0:0:ffff:12.34.56.78');

is(is_ipv6('2067::'),   '2067::', 'is_ipv6 2607::');
is(is_ipv6('2067:::'),  undef,    'is_ipv6 2607:::');
is(is_ipv6('2067:::1'), undef,    'is_ipv6 2607:::1');
is(is_ipv6('2067::1:'), undef,    'is_ipv6 2607::1:');

is(is_ipv6('216.17.184.1'), undef, 'is_ipv6 216.17.184.1');
is(is_ipv6('bbb.bbb.bbb'),  undef, 'is_ipv6 bbb.bbb.bbb');

is(is_linklocal_ipv6('fe80:db8::4'), 'fe80:db8::4', 'is_linklocal_ipv6 fe80:db8::4');
is(is_linklocal_ipv6('fe80:db8'), undef, 'is_linklocal_ipv6 fe80:db8');

