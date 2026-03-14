template '/etc/nginx/conf.d/ssl.conf' do
  source 'ssl.conf.erb'
  variables(
    protocols: 'TLSv1 TLSv1.1',
    ciphers: 'ECDHE-RSA-RC4-SHA:AES128-SHA'
  )
  action :create
end