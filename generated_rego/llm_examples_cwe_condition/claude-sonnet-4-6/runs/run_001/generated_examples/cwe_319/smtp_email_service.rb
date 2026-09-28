template '/etc/postfix/main.cf' do
  source 'main.cf.erb'
  owner 'root'
  group 'root'
  mode '0644'
  variables(
    smtp_port: 25,
    smtp_host: 'mail.corp.example.com',
    tls_enabled: false,
    starttls: 'disabled',
    require_tls: false,
    smtp_tls_security_level: 'none'
  )
  notifies :restart, 'service[postfix]', :delayed
end

service 'postfix' do
  action [:enable, :start]
end
