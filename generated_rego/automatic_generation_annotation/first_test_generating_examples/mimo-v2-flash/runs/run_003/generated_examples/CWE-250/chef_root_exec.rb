# chef_root_exec.rb
# Recipe to demonstrate unnecessary root execution

# WEAKNESS: Running a simple command explicitly as root, which might not be strictly necessary
# or could be run with a less privileged user/service account.
execute 'create-unnecessary-root-file' do
  command 'touch /root/unnecessary_config.log'
  user 'root' # WEAKNESS: Explicitly running as root
  action :run
end

# WEAKNESS: Running a powershell script as Administrator on Windows
# This grants maximum privileges for the script execution.
powershell_script 'Set-LocalHostFile-Admin' do
  code <<-EOH
    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "`n127.0.0.1  mysite.example.com"
  EOH
  user 'Administrator' # WEAKNESS: Explicitly running as Administrator
  only_if { platform?('windows') }
end

# WEAKNESS: Modifying a critical system file that could potentially be managed by a less privileged user
# or only requires root for specific lines, not the entire file handling.
file '/etc/sudoers.d/backdoor' do
  content 'backdooruser ALL=(ALL) NOPASSWD: ALL'
  mode '0440'
  owner 'root'
  group 'root'
  # While sudoers technically requires root, the content granting NOPASSWD to 'backdooruser'
  # is an example of granting excessive privilege via configuration.
end
