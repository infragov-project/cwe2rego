exec { 'configure_interface':
  command => 'sudo ifconfig eth0 192.168.1.10 netmask 255.255.255.0 up',
  path    => '/usr/bin:/sbin:/bin',
  unless  => 'ifconfig eth0 | grep 192.168.1.10',
}