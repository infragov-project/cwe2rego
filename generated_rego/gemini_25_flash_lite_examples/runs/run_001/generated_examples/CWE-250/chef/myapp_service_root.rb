# Ensure the application script exists (not the vulnerability source)
cookbook_file '/usr/local/bin/my_app.sh' do
  source 'my_app.sh' # Assumes my_app.sh is in cookbook_name/files/default/
  mode '0755'
  owner 'root'
  group 'root'
  action :create
end

# Define the systemd service, running as root unnecessarily
systemd_service 'my_app' do
  description 'My Debug Application'
  exec_start '/usr/local/bin/my_app.sh'
  user 'root' # <-- CWE-250: Running as root unnecessarily.
  group 'root' # <-- CWE-250: Running as root unnecessarily.
  restart 'on-failure'
  action [:create, :enable, :start]
end
