#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Dancer::Plugin::Auth::Extensible::Provider::SIP2' ) || print "Bail out!\n";
}

diag( "Testing Dancer::Plugin::Auth::Extensible::Provider::SIP2 $Dancer::Plugin::Auth::Extensible::Provider::SIP2::VERSION, Perl $], $^X" );
