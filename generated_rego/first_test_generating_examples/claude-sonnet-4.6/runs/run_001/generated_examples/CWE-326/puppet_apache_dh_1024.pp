# Assumes the puppetlabs-apache module is installed

class { 'apache':
  default_mods => false,
}

class { 'apache::mod::ssl':
  # CWE-326: Weak Key Length / Key Size - Diffie-Hellman parameters below 2048 bits
  ssl_dhparam_size => 1024, # Explicitly setting a weak DH parameter size
  ssl_cipher_suite => 'HIGH:!aNULL:!MD5:!RC4', # Example with modern ciphers, but weak DH param
  ssl_protocol     => ['all', '-SSLv2', '-SSLv3', '-TLSv1', '-TLSv1.1'], # Modern TLS versions
}

apache::vhost { 'secure.example.com':
  port            => '443',
  docroot         => '/var/www/',
  ssl             => true,
  ssl_certificate => '/etc/ssl/certs/ssl-cert-snakeoil.pem',
  ssl_key         => '/etc/ssl/private/ssl-cert-snakeoil.key',
}