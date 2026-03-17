# Class: my_software::install
# Installs software using an insecure HTTP download.

class my_software::install {
  exec { 'download_insecure_installer':
    command  => '/usr/bin/wget http://downloads.insecure.org/software.zip -O /tmp/software.zip',
    creates  => '/tmp/software.zip',
    path     => ['/usr/bin', '/bin'],
    require  => Package['wget'],
  }

  package { 'wget':
    ensure => present,
  }
}

include my_software::install
