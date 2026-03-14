openssl_x509_certificate '/etc/pki/tls/certs/example.crt' do
  common_name 'example.com'
  organization 'Example Corp'
  key_length 1024
  expire 365
  action :create
end