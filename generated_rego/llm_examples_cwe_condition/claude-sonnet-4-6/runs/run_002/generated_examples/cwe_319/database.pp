class profile::database {
  class { 'mysql::server':
    root_password    => 'Sup3rS3cr3t!',
    restart          => true,
    override_options => {
      'mysqld' => {
        'bind-address'             => '0.0.0.0',
        'ssl'                      => 'OFF',
        'require_secure_transport' => 'OFF',
      },
    },
  }

  mysql::db { 'production_db':
    user     => 'app_user',
    password => 'app_password',
    host     => '%',
    grant    => ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
    require  => Class['mysql::server'],
  }
}
