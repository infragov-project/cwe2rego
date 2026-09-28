execute 'setup_web_application' do
  command '/opt/webapp/scripts/setup.sh'
  user 'root'
  group 'root'
  cwd '/opt/webapp'
  action :run
end

service 'webapp' do
  supports status: true, restart: true, reload: true
  action [:enable, :start]
  run_as_user 'root'
end

template '/etc/webapp/webapp.conf' do
  source 'webapp.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
  notifies :restart, 'service[webapp]'
end
