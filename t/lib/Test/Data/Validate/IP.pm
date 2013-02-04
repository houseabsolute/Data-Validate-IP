package    # hide form PAUSE
    Test::Data::Validate::IP;

use Data::Validate::IP;
use Exporter qw( import );
use Test::More 0.88;

our @EXPORT = 'run_tests';

sub run_tests {

    {
        for my $good (qw(216.17.184.1 0.0.0.0)) {
            is(is_ipv4($good), $good, "is_ipv4($good) returns $good");
        }

        my @bad = qw(
            www.neely.cx
            216.17.184.G
            216.17.184.1.
            216.17.184
            216.17.184.
            256.17.184.1
            216.017.184.1
            016.17.184.1
        );

        for my $bad (@bad) {
            is(is_ipv4($bad), undef, "is_ipv4($bad) returns undef");
        }
    }

    {
        is(
            is_innet_ipv4('216.17.184.1', '216.17.184.0/24'), '216.17.184.1',
            'is_innet_ipv4(216.17.184.1, 216.17.184.0/24) returns 216.17.184.1'
        );
        is(
            is_innet_ipv4('127.0.0.1', '216.17.184.0/24'), undef,
            'is_innet_ipv4(127.0.0.1, 216.17.184.0/24) returns undef'
        );
        is(
            is_innet_ipv4('invalid', '216.17.184.0/24'), undef,
            'is_innet_ipv4(invalid, 216.17.184.0/24) returns undef'
        );
    }

    {
        for my $private (qw(10.0.0.1 172.16.0.1 192.168.0.1)) {
            is(
                is_private_ipv4($private), $private,
                "is_private_ipv4($private) returns $private"
            );
            is(
                is_public_ipv4($private), undef,
                "is_public_ipv4($private) returns undef"
            );
        }

        for my $public (qw(1.2.3.4 123.123.44.55 216.17.184.1)) {
            is(
                is_private_ipv4($public), undef,
                "is_private_ipv4($public) returns undef"
            );
            is(
                is_public_ipv4($public), $public,
                "is_public_ipv4($public) returns $public"
            );
        }

        for my $invalid (qw(ff00:: not-valid)) {
            is(
                is_private_ipv4($invalid), undef,
                "is_private_ipv4($invalid) returns undef"
            );
            is(
                is_public_ipv4($invalid), undef,
                "is_public_ipv4($invalid) returns undef"
            );
        }
    }

    {
        is(
            is_loopback_ipv4('127.0.0.1'), '127.0.0.1',
            'is_loopback_ipv4(127.0.0.1) returns 127.0.0.1'
        );
        is(
            is_loopback_ipv4('4.4.4.4'), undef,
            'is_loopback_ipv4(4.4.4.4) returns undef'
        );
        is(
            is_loopback_ipv4('not an ip'), undef,
            'is_loopback_ipv4(not an ip) returns undef'
        );

        is(
            is_testnet_ipv4('192.0.2.9'), '192.0.2.9',
            'is_testnet_ipv4(192.0.2.9) returns 192.0.2.9'
        );
        is(
            is_testnet_ipv4('127.0.0.1'), undef,
            'is_testnet_ipv4(127.0.0.1) returns undef'
        );
        is(
            is_testnet_ipv4('not an ip'), undef,
            'is_testnet_ipv4(not an ip) returns undef'
        );

        is(
            is_multicast_ipv4('224.0.0.1'), '224.0.0.1',
            'is_multicast_ipv4(224.0.0.1) returns 224.0.0.1'
        );
        is(
            is_multicast_ipv4('216.17.184.1'), undef,
            'is_multicast_ipv4(216.17.184.1) returns undef'
        );
        is(
            is_multicast_ipv4('not an ip'), undef,
            'is_multicast_ipv4(not an ip) returns undef'
        );

        is(
            is_linklocal_ipv4('169.254.0.1'), '169.254.0.1',
            'is_linklocal_ipv4(169.254.0.1) returns 169.254.0.1'
        );
        is(
            is_linklocal_ipv4('216.17.184.1'), undef,
            'is_linklocal_ipv4(216.17.184.1) returns undef'
        );
        is(
            is_linklocal_ipv4('not an ip'), undef,
            'is_linklocal_ipv4(not an ip) returns undef'
        );
    }

    {
        my @good = qw(
            2067:fa88::0
            2067:FA88::1
            2607:fa88::8a2e:370:7334
            2001:0db8:0000:0000:0000:0000:1428:57ab
            2001:0db8:0000:0000:0000::1428:57ab
            2001:0db8:0:0:0:0:1428:57ab
            2001:0db8:0:0::1428:57ab
            2001:0db8::1428:57ab
            2001:db8::1428:57ab
            ::
            ::0
            ::1
            ::ffff:12.34.56.78
            0:0:0:0:0:ffff:12.34.56.78
        );

        for my $good (@good) {
            is(is_ipv6($good), $good, "is_ipv6($good) returns $good");
        }

        my @bad = qw(
            2067:fa88
            2067:FA88
            2067:::
            2067:::1
            2067::1:
            216.17.184.1
            bbb.bbb.bbb
            :::
            g123::1234
        );

        for my $bad (@bad) {
            is(is_ipv6($bad), undef, "is_ipv6($bad) returns undef");
        }
    }

    {
        is(
            is_linklocal_ipv6('fe80:db8::4'), 'fe80:db8::4',
            'is_linklocal_ipv6(fe80:db8::4) returns fe80:db8::4'
        );

        for my $bad (qw(1001:2abc:0:: fe80:db8)) {
            is(
                is_linklocal_ipv6($bad), undef,
                "is_linklocal_ipv6($bad) returns undef"
            );
        }
    }
}

1;
