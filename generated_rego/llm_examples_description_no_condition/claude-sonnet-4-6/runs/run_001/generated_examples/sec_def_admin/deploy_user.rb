user 'deploy_user' do
  comment 'Deployment User'
  groups ['admin', 'sudo', 'wheel']
  shell '/bin/bash'
  home '/home/deploy_user'
  action :create
end

template '/etc/myapp/config.yml' do
  source 'config.yml.erb'
  owner 'root'
  group 'root'
  mode '0644'
  variables(
    db_user: 'admin',
    db_password: 'admin',
    run_as: 'admin'
  )
end
