# manifests/site.pp

class { 'apache':
  mpm_module => 'prefork',
}

class { 'apache::mod::ssl': }

apache::vhost { 'legacy_site':
  port             => 8443,
  docroot          => '/var/www/html/legacy',
  ssl              => true,
  ssl_cipher_suite => 'HIGH:!aNULL:!MD5:!RC4',
  # CWE-326: Outdated Protocols - Explicitly allowing SSLv3 and TLSv1.0 which are deprecated
  ssl_protocol     => 'SSLv3 TLSv1',
  ssl_cert         => '/etc/pki/tls/certs/legacy.crt',
  ssl_key          => '/etc/pki/tls/private/legacy.key',
  require          => Class['apache::mod::ssl'],
}
