# Insecure Nginx SSL configuration
nginx_install 'default'

nginx_app 'secure_site' do
  template 'nginx.app.conf.erb'
  cookbook 'my_nginx_cookbook'
  variables(
    server_name: 'weak.example.com',
    ssl_certificate: '/etc/ssl/certs/nginx-selfsigned.crt',
    ssl_certificate_key: '/etc/ssl/private/nginx-selfsigned.key',
    ssl_protocols: 'TLSv1 TLSv1.1', # CWE-326: Inadequate Encryption Strength (TLSv1 and TLSv1.1 are deprecated and insecure)
    ssl_ciphers: 'RC4-SHA:DES-CBC3-SHA:AES128-SHA', # CWE-326: Inadequate Encryption Strength (RC4, DES-CBC3-SHA are weak ciphers)
    log_dir: '/var/log/nginx'
  )
end

directory '/etc/ssl/private' do
  mode '0700'
  recursive true
end

execute "generate-ssl-key-#{node['hostname']}" do
  command "openssl genrsa -out /etc/ssl/private/nginx-selfsigned.key 1024" # CWE-326: Inadequate Encryption Strength (RSA key size 1024 bits is too small)
  creates '/etc/ssl/private/nginx-selfsigned.key'
end

execute "generate-ssl-cert-#{node['hostname']}" do
  command 'openssl req -x509 -new -nodes -key /etc/ssl/private/nginx-selfsigned.key -days 365 -subj "/CN=weak.example.com" -out /etc/ssl/certs/nginx-selfsigned.crt -sha1' # CWE-326: Inadequate Encryption Strength (SHA1 is a weak digest algorithm)
  creates '/etc/ssl/certs/nginx-selfsigned.crt'
end