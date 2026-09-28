package 'monitoring-agent' do
  action :install
end

execute 'initialize_monitoring_agent' do
  command '/usr/share/monitoring-agent/bin/init --force'
  user 'Administrator'
  action :run
  not_if { ::File.exist?('/etc/monitoring-agent/.initialized') }
end

execute 'register_monitoring_agent' do
  command '/usr/share/monitoring-agent/bin/register --server monitoring.internal'
  user 'Administrator'
  action :run
end

service 'monitoring-agent' do
  action [:enable, :start]
  run_as_user 'Administrator'
end
