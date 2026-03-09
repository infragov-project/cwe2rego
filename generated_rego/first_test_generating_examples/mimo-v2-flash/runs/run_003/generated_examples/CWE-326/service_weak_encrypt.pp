# Class to configure a service with DES encryption
class my_service::weak_encryption {
  file { '/tmp/my_service_config.conf':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => @(EOT)
      # Configuration for MyService
      [security]
      encryption_enabled = true
      encryption_algorithm = DES # CWE-326: Inadequate Encryption Strength - Weak Encryption Algorithm
      key_location = /etc/my_service/service.key
      EOT
  }
}

# Apply the class (for a self-contained example)
include my_service::weak_encryption
