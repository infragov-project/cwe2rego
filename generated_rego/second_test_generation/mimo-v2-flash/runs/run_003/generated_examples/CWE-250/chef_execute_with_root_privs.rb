execute 'run-dangerous-cleanup' do
  command 'rm -rf /'
  user 'root'
  # This command is explicitly run as root and is destructive, demonstrating unnecessary privilege.
  action :run
end

powershell_script 'Set-Localhost-Firewall-Permissive' do
  code 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True; New-NetFirewallRule -DisplayName "Allow All Inbound" -Direction Inbound -Action Allow -Profile Any -LocalPort Any -RemoteAddress Any'
  action :run
  # In Windows, chef-client often runs as Local System, which is equivalent to root.
  # This example directly makes the firewall permissive.
end
