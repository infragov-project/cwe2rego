openssl_certificate 'legacy_signature' do
  path '/etc/ssl/certs/legacy.crt'
  common_name 'legacy.example.com'
  key_length 2048
  digest 'SHA1'
  expire 365
  action :create
end