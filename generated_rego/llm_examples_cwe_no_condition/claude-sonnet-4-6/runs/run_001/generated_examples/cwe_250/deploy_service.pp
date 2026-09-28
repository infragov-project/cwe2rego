class myapp::deploy {

  exec { 'run_myapp_installer':
    command => '/tmp/myapp_installer.sh --auto',
    user    => 'root',
    path    => ['/usr/bin', '/bin', '/usr/sbin'],
    creates => '/opt/myapp/bin/myapp',
  }

  exec { 'initialize_myapp_database':
    command => '/opt/myapp/bin/myapp db:migrate',
    user    => 'root',
    path    => ['/usr/bin', '/bin'],
    require => Exec['run_myapp_installer'],
  }

  service { 'myapp':
    ensure  => running,
    enable  => true,
    require => Exec['initialize_myapp_database'],
  }

}
