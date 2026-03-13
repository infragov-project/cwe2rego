database 'app_db' do
  driver 'mysql'
  host 'db-master.internal'
  port 3306
  username 'admin'
  password 'secret'
  enable_ssl false
  action :create
end
