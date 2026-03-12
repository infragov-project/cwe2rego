remote_file '/var/www/html/app.zip' do
  source 'http://insecure.internal.example.com/builds/app.zip' # CWE-319: Uses HTTP protocol for file download
  owner 'www-data'
  group 'www-data'
  mode '0644'
  action :create
end
