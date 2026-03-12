# chef_db_permissions.rb
# Requires the 'database' cookbook
# Example assumes a local MySQL installation configured

mysql_database_user 'app_user' do
  connection(
    :host     => 'localhost',
    :username => 'root',
    :password => 'root_password'
  )
  password 'super_secret_password'
  database_name 'app_db'
  host '%'
  privileges [:all] # Grants ALL PRIVILEGES - CWE-250
  action :create
  action :grant
end
