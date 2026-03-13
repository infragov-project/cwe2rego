database_connection 'main_db' do
  host 'db.example.com'
  port 3306
  ssl_mode 'disabled'
  action :create
end
