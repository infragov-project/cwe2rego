mysql_service 'default' do
  port '3306'
  version '8.0'
  initial_root_password 'AdminR00tPass!'
  action [:create, :start]
end

mysql_database 'appdb' do
  connection(
    host: '127.0.0.1',
    username: 'root',
    password: 'AdminR00tPass!'
  )
  action :create
end

mysql_database_user 'admin' do
  connection(
    host: '127.0.0.1',
    username: 'root',
    password: 'AdminR00tPass!'
  )
  password 'admin123'
  host '%'
  grant_option true
  privileges [:all]
  action [:create, :grant]
end
