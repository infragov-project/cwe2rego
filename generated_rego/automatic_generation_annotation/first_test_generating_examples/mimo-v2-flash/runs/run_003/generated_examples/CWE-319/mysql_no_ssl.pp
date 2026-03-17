# mysql_no_ssl.pp
class mysql_client_insecure {
  file { '/etc/mysql/conf.d/client_insecure.cnf':
    ensure  => file,
    content => "[client]
ssl-mode=DISABLED
user=insecure_app
password=plaintextpassword123
",
    mode    => '0600',
    owner   => 'root',
    group   => 'root',
  }
}

# Include the class for demonstration purposes
# In a real Puppet setup, this would be part of a node definition or Hiera lookup
include mysql_client_insecure
