# recipes/default.rb

user 'chef_user' do
  home '/home/chef_user'
  manage_home true
  shell '/bin/bash'
  action :create
end

directory '/home/chef_user/my_app' do
  owner 'chef_user'
  group 'chef_user'
  mode '0755'
  recursive true
  action :create
end

# WEAKNESS: Running this copy command as root when it could be run as 'chef_user'
execute 'copy_my_app_config' do
  command "cp /tmp/my_app.conf /home/chef_user/my_app/config.yml"
  user 'root' # CWE-250: Unnecessary privilege, as the target directory is managed by chef_user.
  creates '/home/chef_user/my_app/config.yml'
  action :run
end
