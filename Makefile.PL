#!/usr/bin/perl
use 5.008;
use ExtUtils::MakeMaker;
WriteMakefile(
              NAME         => 'DJabberd::Authen::PAM',
              VERSION_FROM => 'lib/DJabberd/Authen/PAM.pm',
              ABSTRACT_FROM => 'lib/DJabberd/Authen/PAM.pm',
              PREREQ_PM    => {
                  'DJabberd'                => '0.80',
                  'Authen::PAM'             => '0',
              },
              AUTHOR     => 'Brad Fitzpatrick <brad@danga.com>',
              );

