# Cookbook: my_app
# Recipe: default

# This recipe demonstrates unnecessary privilege escalation.

execute 'create-temp-file-sudo' do
  command 'sudo touch /tmp/chef_sudo_test.txt'
  action :run
  # The 'touch' command in /tmp usually does not require sudo.
  # Explicitly using 'sudo' here demonstrates unnecessary privilege escalation.
end

execute 'list-directory-as-root' do
  command 'ls -al /tmp'
  user 'root' # Running a simple directory listing as root is unnecessary.
  action :run
end
