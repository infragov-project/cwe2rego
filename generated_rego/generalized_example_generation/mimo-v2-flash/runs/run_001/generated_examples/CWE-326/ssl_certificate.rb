openssl_x509_certificate '/etc/ssl/cert.pem' do
  common_name 'internal.service'
  key_size 1024
  algorithm 'RSA'
  action :create
end