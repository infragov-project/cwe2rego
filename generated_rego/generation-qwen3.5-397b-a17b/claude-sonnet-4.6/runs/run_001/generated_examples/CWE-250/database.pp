exec { 'create_database_admin':
  command => 'psql -c "CREATE USER admin WITH SUPERUSER PASSWORD \'strongpassword\'"',
  user    => 'postgres',
  unless  => 'psql -t -c "\\du" | grep -q admin',
  path    => ['/usr/bin', '/bin'],
}

postgresql::role { 'root':
  superuser => true,
  createdb  => true,
  createrole => true,
  password  => 'rootpassword',
}