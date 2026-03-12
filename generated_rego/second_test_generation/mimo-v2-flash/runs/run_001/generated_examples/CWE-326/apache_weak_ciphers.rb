#
# Cookbook:: apache_config
# Recipe:: default
#
# A Chef recipe to configure Apache with weak SSL ciphers and protocols.
# This demonstrates CWE-326.
#

package 'apache2' do
  action :install
end

service 'apache2' do
  action [:enable, :start]
end

# Create a dummy ssl.conf.erb file for content
file '/etc/apache2/mods-available/ssl.conf.erb' do
  content <<-EOF
  <IfModule mod_ssl.c>
    <VirtualHost _default_:443>
      ServerAdmin webmaster@localhost
      DocumentRoot /var/www/html

      ErrorLog ${APACHE_LOG_DIR}/error.log
      CustomLog ${APACHE_LOG_DIR}/access.log combined

      SSLEngine on
      SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
      SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

      # CWE-326: Weak Cipher Suites (3DES, RC4) and Outdated Protocols (TLSv1.0, TLSv1.1)
      SSLCipherSuite 3DES-EDE-CBC-SHA:RC4-SHA:AES128-SHA # Explicitly includes 3DES and RC4
      SSLProtocol TLSv1.0 TLSv1.1 TLSv1.2 # Allows TLSv1.0 and TLSv1.1

    </VirtualHost>
  </IfModule>
  EOF
  action :create
end

template '/etc/apache2/mods-available/ssl.conf' do
  source 'ssl.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
  notifies :restart, 'service[apache2]', :immediately
end
