remote_file '/tmp/installer/myapp-2.0.0.rpm' do
  source 'http://packages.example.com/myapp/2.0.0/myapp-2.0.0.rpm'
  owner 'root'
  group 'root'
  mode '0644'
  action :create
end

rpm_package 'myapp' do
  source '/tmp/installer/myapp-2.0.0.rpm'
  action :install
end
