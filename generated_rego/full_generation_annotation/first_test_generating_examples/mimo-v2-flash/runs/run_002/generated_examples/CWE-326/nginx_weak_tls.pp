# Puppet manifest to configure Nginx with weak TLS
class { 'nginx': }

file { '/etc/nginx/conf.d/weak_ssl_site.conf':
  ensure  => file,
  content => @("EOT")
    server {
        listen 443 ssl;
        listen [::]:443 ssl;

        server_name weak.example.com;

        ssl_certificate /etc/nginx/ssl/weak.crt;
        ssl_certificate_key /etc/nginx/ssl/weak.key;

        # CWE-326: Inadequate Encryption Strength - TLSv1.0 and TLSv1.1 included
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        # CWE-326: Inadequate Encryption Strength - RC4 and 3DES ciphers included
        ssl_ciphers "RC4-SHA:3DES-EDE-CBC-SHA:AES128-SHA";

        root /var/www/weak_html;
        index index.html;
    }
    |EOT
,
  owner   => 'root',
  group   => 'root',
  mode    => '0644',
  notify  => Service['nginx'],
}

service { 'nginx':
  ensure    => running,
  enable    => true,
  hasstatus => true,
  hasrestart => true,
}
