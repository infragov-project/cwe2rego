# file: overly_permissive_sudo.rb
# This recipe deploys a user with overly broad sudo access.
# The 'ALL=(ALL:ALL) ALL' rule grants full root access.

user 'devops_user' do
  action :create
  comment 'DevOps User'
  password '$6$rounds=40000$examplesalt$hashedpassword' # Example password
end

sudo 'devops_sudo' do
  user 'devops_user'
  nopasswd true
  commands ['ALL'] # CWE-250: Grants ALL commands without password, violating least privilege.
end