file '/etc/myapp/config.yml' do
  content 'database_url: postgresql://user:pass@host/db'
  mode '0644'
  owner 'root'
  group 'root'
  action :create
end
