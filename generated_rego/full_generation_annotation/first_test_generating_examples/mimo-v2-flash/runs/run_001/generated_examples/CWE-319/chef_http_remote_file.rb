# Cookbook:: my_app
# Recipe:: default

remote_file '/etc/my_app/config.json' do
  source 'http://configs.example.com/production/config.json'
  owner 'appuser'
  group 'appuser'
  mode '0644'
  action :create
end
