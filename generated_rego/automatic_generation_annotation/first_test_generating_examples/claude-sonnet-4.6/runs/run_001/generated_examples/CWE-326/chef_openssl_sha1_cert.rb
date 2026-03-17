# In a Chef recipe for generating an SSL certificate

# Ensure Openssl cookbook is available for openssl_private_key and openssl_x509_certificate resources

directory '/etc/ssl/private' do
  owner 'root'
  group 'root'
  mode '00700'
  recursive true
  action :create
end

directory '/etc/ssl/certs' do
  owner 'root'
  group 'root'
  mode '00755'
  recursive true
  action :create
end

openssl_private_key '/etc/ssl/private/weak-cert-key.pem' do
  key_length 2048
  force true
end

openssl_x509_certificate '/etc/ssl/certs/weak-cert.pem' do
  common_name 'weak.example.com'
  owner 'root'
  group 'root'
  mode '0644'
  # CWE-326: Weak Signing or Certificate Algorithms - explicitly using SHA1 digest
  digest 'sha1' 
  expire 365
  key_file '/etc/ssl/private/weak-cert-key.pem'
  notifies :restart, 'service[dependent_service]', :delayed
end

service 'dependent_service' do
  action :nothing # Placeholder service to show notification
end