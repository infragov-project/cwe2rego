# puppet_broad_network.pp
# Requires the 'firewall' module

# Insecure rule: allow MySQL from anywhere
firewall { '100 allow MySQL from anywhere':
  proto  => 'tcp',
  dport  => '3306',
  source => '0.0.0.0/0', # Unrestricted access from anywhere - CWE-250
  action => 'accept',
}

# Insecure rule: allow RDP from anywhere (for Windows hosts)
firewall { '101 allow RDP from anywhere':
  proto  => 'tcp',
  dport  => '3389',
  source => '0.0.0.0/0', # Unrestricted access from anywhere - CWE-250
  action => 'accept',
}
