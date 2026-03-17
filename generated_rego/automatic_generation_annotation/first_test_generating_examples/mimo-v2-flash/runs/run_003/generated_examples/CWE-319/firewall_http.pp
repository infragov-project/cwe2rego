# firewall_http.pp

# This example assumes the firewalld module is available
# On RHEL/CentOS systems, firewalld is commonly used.
class firewall_open_http {
  package { 'firewalld':
    ensure => installed,
  }

  service { 'firewalld':
    ensure  => running,
    enable  => true,
    require => Package['firewalld'],
  }

  # Explicitly allow HTTP traffic on port 80 for the public zone
  firewalld::port { 'public-http-80':
    ensure    => present,
    zone      => 'public',
    port      => '80/tcp',
    permanent => true,
    # This explicit notify ensures the rule is applied after service restart/reload
    notify    => Service['firewalld'],
  }
}

# Include the class for demonstration purposes
# In a real Puppet setup, this would be part of a node definition or Hiera lookup
include firewall_open_http
