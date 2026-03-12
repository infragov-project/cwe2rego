# chef_apache_rc4_cipher.rb
# Assumes 'apache2' cookbook is depended upon in metadata.rb

# Ensure Apache is installed
include_recipe 'apache2'

# Enable the SSL module for Apache
include_recipe 'apache2::mod_ssl'

apache2_vhost 'default-ssl' do
  port 443
  servername 'localhost'
  docroot '/var/www/html'

  # Configure SSL
  ssl_enable true
  ssl_certificate '/etc/ssl/certs/ssl-cert-snakeoil.pem'
  ssl_certificate_key '/etc/ssl/private/ssl-cert-snakeoil.key'
  ssl_cipher_suite 'RC4-SHA:AES128-SHA' # CWE-326: Weak Encryption Algorithms (RC4 cipher)
  ssl_protocol 'All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1' # Protocols are okay, but cipher is weak
  action :create
  notifies :restart, 'service[apache2]'
end

service 'apache2' do
  action [:enable, :start]
end
