# This recipe configures Nginx to listen on HTTP port 80 without SSL.
package 'nginx' do
  action :install
end

file '/etc/nginx/sites-available/default' do
  content <<-EOF
server {
    listen 80;
    listen [::]:80;
    server_name localhost;
    root /var/www/html;
    index index.html;
    # No SSL/TLS configuration present for this server block
    # No redirect to HTTPS
}
      EOF
  owner 'root'
  group 'root'
  mode '0644'
  notifies :reload, 'service[nginx]', :immediately
end

service 'nginx' do
  action [:enable, :start]
end
