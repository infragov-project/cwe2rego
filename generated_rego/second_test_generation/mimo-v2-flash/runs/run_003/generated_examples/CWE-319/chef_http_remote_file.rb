remote_file '/var/www/html/insecure_app/index.html' do
  source 'http://repo.example.com/web_content/index.html'
  owner 'www-data'
  group 'www-data'
  mode '0644'
  action :create
end
