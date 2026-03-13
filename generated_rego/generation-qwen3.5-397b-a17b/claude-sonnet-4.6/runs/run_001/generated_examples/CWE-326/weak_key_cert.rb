openssl_certificate 'weak_rsa_key' do
  path '/etc/ssl/certs/server.crt'
  common_name 'example.com'
  key_length 1024
  expire 365
  action :create
end