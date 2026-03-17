openssl_x509_certificate '/etc/ssl/certs/server.crt' do
  private_key '/etc/ssl/private/server.key'
  key_length 1024
  algorithm 'RSA'
  expire 365
  action :create
end