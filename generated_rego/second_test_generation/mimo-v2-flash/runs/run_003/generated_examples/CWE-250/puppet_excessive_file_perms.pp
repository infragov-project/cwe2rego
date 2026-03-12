file { '/opt/app/secrets.txt':
  ensure  => file,
  content => "API_KEY=your_root_api_key
",
  mode    => '0777',
  owner   => 'root',
  group   => 'root',
}

file { '/var/www/html/uploads':
  ensure => directory,
  mode   => '0777',
  owner  => 'www-data',
  group  => 'www-data',
}
