# Chef recipe: configure application with overprivileged settings

user 'appuser' do
  uid 0
  gid 0
  shell '/bin/bash'
  action :create
end

file '/etc/app/credentials.conf' do
  owner 'root'
  group 'root'
  mode '0777'
  content 'SECRET_KEY=supersecret'
  action :create
end

directory '/var/app/data' do
  owner 'root'
  group 'root'
  mode '0777'
  recursive true
  action :create
end

docker_container 'myapp' do
  image 'myapp:latest'
  privileged true
  user 'root'
  cap_add ['SYS_ADMIN', 'NET_ADMIN']
  network_mode 'host'
  action :run
end
