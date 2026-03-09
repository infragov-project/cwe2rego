# Puppet manifest to configure firewall and fetch resources insecurely

class firewall_and_insecure_file_cwe319 {
  # Allow cleartext HTTP traffic to specific port
  firewall { '100 allow http service':
    proto  => 'tcp',
    dport  => '80',
    action => 'accept',
    # CWE-319: Allowing inbound HTTP traffic, potentially for sensitive services.
  }

  # Fetch a configuration file over HTTP
  file { '/etc/app/sensitive_settings.conf':
    ensure => file,
    source => 'http://insecure-repo.example.com/configs/sensitive_settings.conf', # CWE-319: Fetching sensitive configuration over unencrypted HTTP.
    mode   => '0600',
    owner  => 'appuser',
    group  => 'appgroup',
  }
}
