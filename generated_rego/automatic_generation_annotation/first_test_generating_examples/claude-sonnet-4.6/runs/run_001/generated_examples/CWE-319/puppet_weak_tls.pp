# puppet_weak_tls.pp
# A Puppet manifest to configure an application with a weak TLS version and disabled SSL verification.

file { '/etc/appdaemon/security.conf':
  ensure  => file,
  content => '[tls]
enabled = true
# This application is deliberately configured with a weak TLS version
min_tls_version = TLSv1.0 # Using an outdated and weak TLS version (CWE-319)
certificate_path = /etc/appdaemon/certs/app.crt
private_key_path = /etc/appdaemon/certs/app.key
ssl_verify = false # Explicitly disabling SSL verification (CWE-319)
',
  mode    => '0644',
  owner   => 'root',
  group   => 'root',
}

service { 'appdaemon':
  ensure    => running,
  enable    => true,
  subscribe => File['/etc/appdaemon/security.conf'],
}
