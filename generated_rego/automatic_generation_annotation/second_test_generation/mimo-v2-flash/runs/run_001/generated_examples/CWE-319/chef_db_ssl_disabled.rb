# /cookbooks/my_app/recipes/database_config.rb
directory '/etc/my_app' do
  owner 'root'
  group 'root'
  mode '0755'
  action :create
end

file '/etc/my_app/database.ini' do
  content <<-EOC
[database]
type = postgresql
host = mydatabase.example.com
port = 5432
user = app_user
password = app_plaintext_password # Also a plaintext secret
sslmode_option = disable # CWE-319: Explicitly disabling SSL for database communication
EOC
  owner 'root'
  group 'root'
  mode '0600'
end
