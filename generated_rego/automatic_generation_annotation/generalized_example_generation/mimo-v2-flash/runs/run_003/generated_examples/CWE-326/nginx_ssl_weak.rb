nginx_server 'example.com' do
  ssl_protocols 'SSLv3 TLSv1 TLSv1.1'
  ssl_ciphers 'RC4-SHA:DES-CBC3-SHA'
end