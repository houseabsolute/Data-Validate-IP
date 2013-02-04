use strict;
use warnings;

use lib 't/lib';

BEGIN {
    $ENV{DVI_NO_SOCKET} = 1;
}

use Test::Data::Validate::IP;
use Test::More 0.88;

run_tests();

done_testing();
