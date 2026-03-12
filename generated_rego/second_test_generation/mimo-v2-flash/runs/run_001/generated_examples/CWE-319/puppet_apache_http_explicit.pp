# modules/apache/manifests/http_site.pp
class apache::http_site (
  $docroot    = '/var/www/html',
  $servername = $::fqdn,
) {
  package { 'apache2':
    ensure => installed,
  }

  file { '/etc/apache2/sites-available/http_default.conf':
    ensure  => file,
    content => "# This is an Apache HTTP VirtualHost configuration
<VirtualHost *:80> # CWE-319: Explicitly listening on HTTP port 80
    ServerAdmin webmaster@localhost
    DocumentRoot ${docroot}
    ServerName ${servername}
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>",
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Package['apache2'],
    notify  => Service['apache2'],
  }

  file { '/etc/apache2/sites-enabled/http_default.conf':
    ensure  => link,
    target  => '/etc/apache2/sites-available/http_default.conf',
    require => File['/etc/apache2/sites-available/http_default.conf'],
    notify  => Service['apache2'],
  }

  service { 'apache2':
    ensure => running,
    enable => true,
  }
}

# In site.pp or another top-level manifest:
# include apache::http_site
