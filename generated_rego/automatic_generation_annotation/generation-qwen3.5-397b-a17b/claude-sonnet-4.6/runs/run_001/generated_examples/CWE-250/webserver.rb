service 'nginx' do
  action [:enable, :start]
  user 'root'
  supports status: true, restart: true, reload: true
end

execute 'start-custom-service' do
  command '/opt/bin/startup.sh'
  user 'root'
  environment({ 'PATH' => '/usr/bin:/bin' })
  action :run
end