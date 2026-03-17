# Cookbook: my_app
# Recipe: default

# Create an application admin user with sudo privileges
user 'app_admin' do
  comment 'Application Administrator'
  password '$6$rounds=someencryptkey$somehashhere' # A placeholder for a hashed password
  manage_home true
  home '/home/app_admin'
  shell '/bin/bash'
  groups ['sudo'] # Assigning to the sudo group grants full elevated privileges unnecessarily for app administration.
  append true
  action :create
end

user 'ops_user' do
  comment 'Operations User'
  password '$6$rounds=anotherkey$anotherhash'
  manage_home true
  home '/home/ops_user'
  shell '/bin/bash'
  groups ['wheel'] # On RHEL-based systems, 'wheel' group grants sudo privileges, often an over-privilege.
  append true
  action :create
end
