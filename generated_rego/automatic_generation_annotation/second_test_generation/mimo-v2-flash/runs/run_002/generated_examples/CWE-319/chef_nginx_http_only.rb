file '/etc/nginx/sites-available/insecureapp' do
  content <<~EOH
    server {
        listen 80; # CWE-319: Configures an HTTP listener without SSL/TLS enforcement
        server_name insecure.example.com;
        root /var/www/insecure_app;

        location / {
            index index.html index.htm;
            try_files $uri $uri/ =404;
        }
    }
  EOH
  notifies :reload, 'service[nginx]', :delayed
end

service 'nginx' do
  action :nothing
end
