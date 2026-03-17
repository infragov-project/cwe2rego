# chef/cookbooks/myapp/recipes/default.rb

openssl_x509_certificate '/etc/ssl/certs/self_signed.pem' do
  common_name 'example.com'
  org 'Example Corp'
  org_unit 'IT'
  country 'US'
  key_file '/etc/ssl/private/self_signed.key'
  key_type :rsa
  # CWE-326: Inadequate Key Length - RSA key size 1024 bits is too weak for modern security standards
  key_length 1024
  expire 365
  owner 'root'
  group 'root'
  mode '0644'
end
