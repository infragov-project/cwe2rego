#
# Cookbook:: certificate
# Recipe:: weak_x509
#
# A Chef recipe to generate an X.509 certificate and key with weak security parameters.
# This demonstrates CWE-326.
#

directory '/etc/ssl/certs' do
  owner 'root'
  group 'root'
  mode '0755'
  recursive true
  action :create
end

directory '/etc/ssl/private' do
  owner 'root'
  group 'ssl-cert'
  mode '0710'
  recursive true
  action :create
end

# CWE-326: Insufficient Key Lengths (RSA 1024)
# CWE-326: Weak Cryptographic Algorithms (SHA1 for digest)
execute 'generate_weak_ssl_cert' do
  command <<-EOC
    openssl genrsa -out /etc/ssl/private/weak_cert.key 1024 && \
    openssl req -new -key /etc/ssl/private/weak_cert.key -out /tmp/weak_cert.csr -subj "/CN=weak.example.com" -sha1 && \
    openssl x509 -req -days 365 -in /tmp/weak_cert.csr -signkey /etc/ssl/private/weak_cert.key -out /etc/ssl/certs/weak_cert.crt -sha1
  EOC
  cwd '/tmp'
  creates '/etc/ssl/certs/weak_cert.crt'
end

# Dummy Apache service for notification context if applicable
service 'apache2' do
  action :nothing # Only acts if notified
end
