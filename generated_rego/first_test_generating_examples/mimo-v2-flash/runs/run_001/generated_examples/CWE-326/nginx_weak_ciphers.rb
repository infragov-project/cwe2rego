# chef/cookbooks/webserver/recipes/nginx_ssl.rb

file '/etc/nginx/conf.d/ssl.conf' do
  content <<-EOF
    server {
      listen 443 ssl;
      listen [::]:443 ssl;

      ssl_certificate /etc/nginx/certs/server.crt;
      ssl_certificate_key /etc/nginx/certs/server.key;

      # CWE-326: Weak Cipher Suites - Uses RC4 and DES ciphers, which are considered insecure.
      # MD5 is also a weak hashing algorithm for encryption contexts.
      ssl_ciphers 'RC4-SHA:HIGH:!aNULL:!MD5:!DES';
      ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
      ssl_prefer_server_ciphers on;

      root /usr/share/nginx/html;
      index index.html index.htm;

      server_name example.com;

      location / {
        try_files $uri $uri/ =404;
      }
    }
  EOF
  owner 'root'
  group 'root'
  mode '0644'
  notifies :reload, 'service[nginx]', :delayed
end

service 'nginx' do
  action [:enable, :start]
end
