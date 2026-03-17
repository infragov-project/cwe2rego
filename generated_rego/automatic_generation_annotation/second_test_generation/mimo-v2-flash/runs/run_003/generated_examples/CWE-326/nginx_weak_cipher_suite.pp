# This configures an Nginx vhost with a weak SSL cipher suite.
# Using 'nginx' module from Puppet Forge as an example.

nginx::resource::vhost { 'weak_ssl.example.com':
  ensure      => present,
  listen_port => 443,
  ssl         => true,
  # Explicitly permitting weak cipher suites, including explicitly listed ones from CWE description
  ssl_ciphers => 'RC4-SHA:DES-CBC3-SHA:AES128-SHA', # Weak cipher suite due to RC4, 3DES, AES128-SHA
  # Also allowing older TLS versions
  ssl_protocol => 'TLSv1.2 TLSv1.1 TLSv1', # Still allows TLSv1 and TLSv1.1
  require     => Class['nginx'],
}

class { 'nginx': }
