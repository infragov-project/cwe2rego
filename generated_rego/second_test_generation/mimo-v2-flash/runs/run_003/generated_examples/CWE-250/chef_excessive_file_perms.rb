file '/etc/app/config.json' do
  content '{"api_key": "supersecret"}'
  mode '0777'
  owner 'root'
  group 'root'
end

directory '/opt/app/data' do
  owner 'appuser'
  group 'appgroup'
  mode '0777'
  action :create
end
