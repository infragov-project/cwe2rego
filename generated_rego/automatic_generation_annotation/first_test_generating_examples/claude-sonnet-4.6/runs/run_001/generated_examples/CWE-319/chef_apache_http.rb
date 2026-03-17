# chef_apache_http.rb
# A Chef recipe to configure an Apache HTTP server listening only on port 80.

package 'apache2' do
  action :install
end

service 'apache2' do
  action [:enable, :start]
end

# Explicitly configure Apache to listen on port 80, overriding any default HTTPS configuration.
file '/etc/apache2/ports.conf' do
  content 'Listen 80
' # Only listens on HTTP port 80
  mode '0644'
  notifies :restart, 'service[apache2]', :delayed
end

# Configure a default site for HTTP traffic on port 80.
file '/etc/apache2/sites-available/000-default.conf' do
  content '<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    # No HTTPS redirect or SSL configuration is present.
</VirtualHost>'
  mode '0644'
  notifies :reload, 'service[apache2]', :delayed
end

# Enable the default site configuration.
link '/etc/apache2/sites-enabled/000-default.conf' do
  to '/etc/apache2/sites-available/000-default.conf'
  notifies :reload, 'service[apache2]', :delayed
end
