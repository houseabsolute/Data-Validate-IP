use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Data::Validate::IP',
    VERSION_FROM      => 'lib/Data/Validate/IP.pm', # finds $VERSION
    LICENSE	=>	'perl',
    PREREQ_PM         => {
				Net::Netmask	=> 0,
				Test::More	=> 0,
#				Net::IPv6Addr	=> 0,
			},
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Data/Validate/IP.pm', # retrieve abstract from module
       AUTHOR         => 'Neil Neely <neil@neely.cx>') : ()),
);
