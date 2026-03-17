# Recipe: application_setup
# Configures application directories

directory '/opt/app/logs/debug' do
  owner 'appuser'
  group 'appgroup'
  mode '0777' # CWE-250: Overly permissive directory permissions for logs
  action :create
end
