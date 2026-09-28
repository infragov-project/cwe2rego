# Puppet manifest: application setup with unnecessary privilege escalation

class app::setup {
  file { '/var/app':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0777',
  }

  file { '/var/app/run.sh':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0777',
    content => "#!/bin/bash
sudo /opt/app/server --privileged
",
  }

  exec { 'initialize_app':
    command => '/usr/bin/sudo /var/app/run.sh',
    user    => 'root',
    require => File['/var/app/run.sh'],
  }

  file { '/etc/sudoers.d/appuser':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0777',
    content => "appuser ALL=(ALL) NOPASSWD: ALL
",
  }
}
