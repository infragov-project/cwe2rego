# Recipe: security_config
# Configures sudo privileges for a specific group.

file '/etc/sudoers.d/developers_sudo' do
  content 'developers ALL=(ALL:ALL) NOPASSWD: ALL' # CWE-250: Granting a 'developers' group full, passwordless sudo access
  owner 'root'
  group 'root'
  mode '00440'
  action :create
end
