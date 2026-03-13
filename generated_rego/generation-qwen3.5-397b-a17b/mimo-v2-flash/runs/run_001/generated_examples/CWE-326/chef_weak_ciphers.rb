nginx_site 'secure_site' do
  ssl true
  ssl_protocols 'TLSv1'
  ssl_ciphers 'RC4-SHA:DES-CBC3-SHA:AES128-SHA'
  action :create
end
