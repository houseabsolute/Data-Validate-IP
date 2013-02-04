package    # hide form PAUSE
    Test::Data::Validate::IP;

use strict;
use warnings;

use Data::Validate::IP;
use Exporter qw( import );
use Test::More 0.88;

our @EXPORT = 'run_tests';

my $object = Data::Validate::IP->new();

my %ipv4_types = (
    private    => [qw(10.0.0.1 172.16.0.1 192.168.0.1)],
    public     => [qw(1.2.3.4 123.123.44.55 216.17.184.1)],
    loopback   => [qw(127.0.0.1)],
    testnet    => [qw(192.0.2.9)],
    multicast  => [qw(224.0.0.1)],
    linklocal  => [qw(169.254.0.1)],
    unroutable => [
        qw(
            0.0.0.1
            100.64.1.2
            192.0.0.4
            198.18.0.55
            203.0.113.44
            240.0.0.4
            255.255.255.254
            255.255.255.255
            )
    ],
);

my %ipv6_types = (
    private => [
        qw(
            fc00::
            fc01::1234
            fdef::
            fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
            )
    ],
    public    => [qw(::abcd:1234 1:: 2:: 1:1:1:1:: abcd::)],
    loopback  => [qw(::1)],
    multicast => [
        qw(
            ff00::
            ffff::
            ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
            )
    ],
    linklocal => [
        qw(
            fe80::
            fe89::
            febf::
            febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
            )
    ],
);

sub run_tests {
    _ipv4_basic_tests();
    _type_tests(\%ipv4_types, 4);
    _ipv4_innet_tests();

    _ipv6_basic_tests();
    _type_tests(\%ipv6_types, 6);
}

sub _ipv4_basic_tests {
    my @valid_ipv4 = qw(
        0.0.0.0
        1.2.3.4
        216.17.184.1
        255.255.255.255
    );

    for my $ip (@valid_ipv4) {
        is(is_ipv4($ip),          $ip, "is_ipv4($ip) returns $ip");
        is($object->is_ipv4($ip), $ip, "->is_ipv4($ip) returns $ip");
    }

    my @invalid_ipv4 = qw(
        www.neely.cx
        216.17.184.G
        216.17.184.1.
        216.17.184
        216.17.184.
        256.17.184.1
        216.017.184.1
        016.17.184.1
    );

    for my $ip (@invalid_ipv4) {
        is(is_ipv4($ip),          undef, "is_ipv4($ip) returns undef");
        is($object->is_ipv4($ip), undef, "->is_ipv4($ip) returns undef");

        for my $type (sort keys %ipv4_types) {
            my ($is_sub_name, $is_sub) = _sub_for_type($type, 4);

            is($is_sub->($ip), undef, "$is_sub_name($ip) returns undef");
            is(
                $object->$is_sub_name($ip), undef,
                "->$is_sub_name($ip) returns undef"
            );
        }
    }
}

sub _ipv4_innet_tests {
    my @tests = (
        [ '216.17.184.1', '216.17.184.0/24', 1 ],
        [ '127.0.0.1',    '216.17.184.0/24', 0 ],
        [ 'invalid',      '216.17.184.0/24', 0 ],
        [ '1.2.3.4',      'default',         1 ],
    );

    for my $triplet (@tests) {
        my ($ip, $network, $is_member) = @{$triplet};

        my $expect = $is_member ? $ip : undef;

        my $expect_string = $expect || 'undef';
        is(
            is_innet_ipv4($ip, $network), $expect,
            "is_innet_ipv4($ip, $network) returns $expect_string"
        );
    }
}

sub _ipv6_basic_tests {
    my @valid = qw(
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

    for my $ip (@valid) {
        is(is_ipv6($ip),          $ip, "is_ipv6($ip) returns $ip");
        is($object->is_ipv6($ip), $ip, "->is_ipv6($ip) returns $ip");
    }

    my @invalid = qw(
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

    for my $ip (@invalid) {
        is(is_ipv6($ip),          undef, "is_ipv6($ip) returns undef");
        is($object->is_ipv6($ip), undef, "->is_ipv6($ip) returns undef");
    }
}

sub _type_tests {
    my $types     = shift;
    my $ip_number = shift;

    my @types = sort keys %{$types};

    for my $type (@types) {
        for my $ip (@{ $types->{$type} }) {
            my ($is_sub_name, $is_sub) = _sub_for_type($type, $ip_number);

            is($is_sub->($ip), $ip, "$is_sub_name($ip) returns $ip");
            is(
                $object->$is_sub_name($ip), $ip,
                "->$is_sub_name($ip) returns $ip"
            );

            for my $other (grep { $_ ne $type } @types) {
                my ($isnt_sub_name, $isnt_sub)
                    = _sub_for_type($other, $ip_number);

                is(
                    $isnt_sub->($ip), undef,
                    "$isnt_sub_name($ip) returns undef"
                );
                is(
                    $object->$isnt_sub_name($ip), undef,
                    "->$isnt_sub_name($ip) returns undef"
                );
            }
        }
    }
}

sub _sub_for_type {
    my $type      = shift;
    my $ip_number = shift;

    my $sub_name = 'is_' . $type . '_ipv' . $ip_number;
    my $sub      = do {
        no strict 'refs';
        \&{$sub_name};
        }
        or die "No sub named $sub_name was not imported";

    return ($sub_name, $sub);
}

1;
