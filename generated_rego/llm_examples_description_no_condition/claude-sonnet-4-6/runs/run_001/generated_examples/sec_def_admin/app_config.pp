class app_config {
  user { 'appuser':
    ensure => present,
    groups => ['admin', 'wheel'],
    shell  => '/bin/bash',
    home   => '/home/appuser',
  }

  file { '/etc/app/settings.conf':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    content => "username=admin
password=admin
role=administrator
",
  }
}
