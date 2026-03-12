# /cookbooks/my_webserver/recipes/default.rb
package 'apache2' do
  action :install
end

file '/etc/apache2/sites-available/000-default.conf' do
  content <<-EOC
<VirtualHost *:80> # CWE-319: Explicitly listening on HTTP port 80
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOC
  owner 'root'
  group 'root'
  mode '0644'
  notifies :restart, 'service[apache2]', :immediately
end

link '/etc/apache2/sites-enabled/000-default.conf' do
  to '/etc/apache2/sites-available/000-default.conf'
  notifies :restart, 'service[apache2]', :immediately
end

service 'apache2' do
  action [:enable, :start]
end
