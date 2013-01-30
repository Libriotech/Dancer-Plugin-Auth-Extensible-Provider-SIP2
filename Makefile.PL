use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Dancer::Plugin::Auth::Extensible::Provider::SIP2',
    AUTHOR           => q{Magnus Enger <magnus@enger.priv.no>},
    VERSION_FROM     => 'lib/Dancer/Plugin/Auth/Extensible/Provider/SIP2.pm',
    ABSTRACT_FROM    => 'lib/Dancer/Plugin/Auth/Extensible/Provider/SIP2.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Dancer-Plugin-Auth-Extensible-Provider-SIP2-*' },
);
