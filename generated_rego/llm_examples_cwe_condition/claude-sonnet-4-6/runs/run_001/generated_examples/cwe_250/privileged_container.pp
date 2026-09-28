# Puppet manifest: deploy Docker container with excessive privileges

class app::container {
  docker::run { 'privileged-app':
    image            => 'myapp:latest',
    privileged       => true,
    username         => 'root',
    extra_parameters => [
      '--cap-add=ALL',
      '--net=host',
      '--pid=host',
      '--ipc=host',
    ],
    volumes          => [
      '/:/host_root:rw',
      '/etc:/host_etc:rw',
    ],
    env              => [
      'RUN_AS_USER=root',
    ],
  }

  docker_compose { '/opt/app/docker-compose.yml':
    ensure  => present,
    scale   => {
      'app' => 1,
    },
    require => Docker::Run['privileged-app'],
  }
}
