# nginx_http.rb

package 'nginx' do
  action :install
end

service 'nginx' do
  action [:enable, :start]
end

file '/etc/nginx/sites-available/default' do
  content <<-EOF
server {
    listen 80 default_server; # CWE-319
    listen [::]:80 default_server; # CWE-319

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }
}
EOF
  notifies :reload, 'service[nginx]'
end

link '/etc/nginx/sites-enabled/default' do
  to '/etc/nginx/sites-available/default'
end
