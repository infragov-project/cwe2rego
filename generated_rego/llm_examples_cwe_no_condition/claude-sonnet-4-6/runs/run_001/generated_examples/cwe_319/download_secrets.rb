remote_file '/etc/myapp/secrets.json' do
  source 'http://artifacts.example.com/private/secrets.json'
  owner 'root'
  group 'root'
  mode '0600'
  action :create
end

template '/etc/myapp/config.yml' do
  source 'config.yml.erb'
  variables(
    db_password: 'cleartext_db_password',
    callback_url: 'http://webhook.example.com/notify'
  )
  sensitive true
  action :create
end
