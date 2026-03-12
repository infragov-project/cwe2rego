# chef_weak_openssl_csr_rsa1024.rb
# Assumes `openssl` cookbook is depended upon to provide `openssl_x509_csr` and `openssl_rsa_key` resources

# Creates an RSA private key with a weak key length
openssl_rsa_key '/etc/ssl/private/weak_rsa_key.pem' do
  owner 'root'
  group 'root'
  mode '0600'
  key_length 1024 # CWE-326: Insufficient Key Sizes (RSA < 2048 bits)
  action :create
end

# Creates a certificate signing request using the weak RSA private key
openssl_x509_csr '/etc/ssl/private/weak_rsa_csr.csr' do
  owner 'root'
  group 'root'
  mode '0640'
  common_name 'weak-cert.example.com'
  key_file '/etc/ssl/private/weak_rsa_key.pem'
  # key_length 1024 implicitly inherited or explicitly configured if resource supported
  action :create
end
