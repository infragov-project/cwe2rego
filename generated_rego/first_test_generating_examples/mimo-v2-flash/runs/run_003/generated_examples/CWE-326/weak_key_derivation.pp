# Class to demonstrate weak key derivation settings
class system::weak_crypt_settings {
  file { '/tmp/pbkdf_config.conf':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => @(EOT)
      # PBKDF2 configuration for system authentication
      [pbkdf2]
      enabled = true
      pbkdf2_iterations = 1000 # CWE-326: Inadequate Encryption Strength - Insecure Key Management (Low PBKDF2 iterations)
      salt_length = 16
      EOT
  }
}

# Apply the class
include system::weak_crypt_settings
