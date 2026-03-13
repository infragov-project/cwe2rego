execute 'run_maintenance_script' do
  command '/opt/scripts/maintenance.sh'
  user 'root'
  action :run
end