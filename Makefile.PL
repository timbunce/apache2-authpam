use ExtUtils::MakeMaker;

unless (eval { require 5.006 }) {
    warn $@;
    exit 0;
}

WriteMakefile(
    NAME		=> 'Apache2::AuthPAM',
    VERSION_FROM	=> 'AuthPAM.pm', # finds $VERSION
    PREREQ_PM		=> {
        'Authen::PAM' => 0.13,
    },
    ABSTRACT_FROM   => 'AuthPAM.pm', # retrieve abstract from module
    AUTHOR          => 'Tim Bunce',
);
