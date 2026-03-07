# Insecure Apache SSL configuration
class { 'apache':
  default_mods     => false,
  mpm_module       => 'event',
  default_vhost    => false,
  purge_configs    => true,
}

# Explicitly configure weak SSL protocols and ciphers
class { 'apache::mod::ssl':
  ssl_cipher       => 'RC4-SHA:DES-CBC3-SHA:AES128-SHA', # CWE-326: Inadequate Encryption Strength (RC4, DES-CBC3-SHA are weak ciphers)
  ssl_protocol     => 'TLSv1 TLSv1.1', # CWE-326: Inadequate Encryption Strength (TLSv1 and TLSv1.1 are deprecated and insecure)
}

exec { 'generate_weak_ssl_key':
  command   => '/usr/bin/openssl genrsa -out /etc/pki/tls/private/weak.example.com.key 1024', # CWE-326: Inadequate Encryption Strength (RSA key size 1024 bits is too small)
  creates   => '/etc/pki/tls/private/weak.example.com.key',
  path      => '/usr/bin:/bin',
} ->
exec { 'generate_weak_ssl_cert':
  command   => '/usr/bin/openssl req -x509 -new -nodes -key /etc/pki/tls/private/weak.example.com.key -days 365 -subj "/CN=weak.example.com" -out /etc/pki/tls/certs/weak.example.com.crt -sha1', # CWE-326: Inadequate Encryption Strength (SHA1 is a weak digest algorithm)
  creates   => '/etc/pki/tls/certs/weak.example.com.crt',
  path      => '/usr/bin:/bin',
}

apache::vhost { 'weak.example.com':
  port            => '443',
  docroot         => '/var/www/weak',
  ssl             => true,
  ssl_cert        => '/etc/pki/tls/certs/weak.example.com.crt',
  ssl_key         => '/etc/pki/tls/private/weak.example.com.key', 
}