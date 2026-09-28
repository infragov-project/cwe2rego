class database::server {

  class { 'postgresql::server':
    postgres_password => 'admin123',
    listen_addresses  => '*',
    ip_mask_allow_all_users => '0.0.0.0/0',
  }

  postgresql::server::role { 'admin':
    superuser     => true,
    createdb      => true,
    createrole    => true,
    login         => true,
    password_hash => postgresql_password('admin', 'admin123'),
  }

  postgresql::server::db { 'appdb':
    user     => 'admin',
    password => postgresql_password('admin', 'admin123'),
  }

  postgresql::server::pg_hba_rule { 'allow all connections':
    description => 'Allow admin from anywhere',
    type        => 'host',
    database    => 'all',
    user        => 'admin',
    address     => '0.0.0.0/0',
    auth_method => 'md5',
  }
}
