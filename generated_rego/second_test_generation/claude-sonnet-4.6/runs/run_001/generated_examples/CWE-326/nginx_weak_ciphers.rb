# A Chef recipe that configures Nginx with weak cipher suites.
# This would typically be part of a larger Nginx cookbook,
# utilizing a template to set Nginx configuration.

nginx_install 'nginx' do
  action :install
end

nginx_service 'nginx' do
  action [:enable, :start]
end

nginx_site 'default' do
  template 'nginx_ssl.conf.erb'
  variables(
    listen_port: 443,
    server_name: 'weak.example.com',
    ssl_certificate: '/etc/nginx/ssl/weak.pem',
    ssl_certificate_key: '/etc/nginx/ssl/weak.key',
    # CWE-326: Explicitly setting weak cipher suites
    ssl_ciphers: 'DES-CBC3-SHA:RC4-SHA:EXPORT-DES-CBC-SHA', # Contains DES, RC4, EXPORT
    ssl_protocols: 'TLSv1.2 TLSv1.1 TLSv1' # Also includes weak TLSv1 for completeness
  )
  notifies :reload, 'nginx_service[nginx]'
end