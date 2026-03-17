# Chef recipe to set up an Nginx site listening only on HTTP

file '/etc/nginx/sites-available/insecure_app' do
  content <<-EOF
server {
    listen 80;
    # CWE-319: Explicitly configuring Nginx to listen only on HTTP (port 80),
    # without a corresponding HTTPS listener, for a potentially sensitive application.

    server_name insecure_app.example.com;
    root /var/www/insecure_app;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
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
