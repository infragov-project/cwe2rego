file { '/etc/storage/volume_config.yaml':
  ensure  => file,
  content => "---
encryption:
  enabled: false
  algorithm: AES-256 # Weakness: Encryption explicitly disabled for a sensitive resource
",
  owner   => 'root',
  group   => 'root',
  mode    => '0644',
}
