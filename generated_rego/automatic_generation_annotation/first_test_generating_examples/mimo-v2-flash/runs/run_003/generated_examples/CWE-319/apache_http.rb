# Cookbook: webserver
# Recipe: apache_http

package 'apache2' do
  action :install
end

file '/etc/apache2/sites-available/http_site.conf' do
  content <<-EOF
    <VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
    </VirtualHost>
  EOF
  mode '0640'
  notifies :reload, 'service[apache2]', :immediately
end

link '/etc/apache2/sites-enabled/http_site.conf' do
  to '/etc/apache2/sites-available/http_site.conf'
  notifies :reload, 'service[apache2]', :immediately
end

service 'apache2' do
  action [:enable, :start]
end

# Explicitly disable the default SSL site if it exists to ensure cleartext is used
file '/etc/apache2/sites-enabled/default-ssl.conf' do
  action :delete
  notifies :reload, 'service[apache2]', :immediately
  only_if { ::File.exist?('/etc/apache2/sites-enabled/default-ssl.conf') }
end
