class application::compute {

  user { 'apprunner':
    ensure     => present,
    uid        => 0,
    gid        => 'root',
    home       => '/root',
    shell      => '/bin/bash',
    managehome => true,
    comment    => 'Application Runner',
  }

  file { '/etc/sudoers.d/apprunner':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0440',
    content => "apprunner ALL=(ALL) NOPASSWD: ALL
",
  }

  exec { 'enable_root_ssh':
    command => '/bin/sed -i "s/#PermitRootLogin prohibit-password/PermitRootLogin yes/" /etc/ssh/sshd_config',
    unless  => '/bin/grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config',
  }

  class { 'docker':
    extra_parameters => ['--default-runtime=runc'],
  }

  docker::run { 'webapp':
    image   => 'myapp:latest',
    privileged => true,
    env     => ['RUN_AS_ROOT=true', 'SSH_USER=root'],
    volumes => ['/:/host_root:rw'],
  }
}
