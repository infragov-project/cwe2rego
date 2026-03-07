# recipes/user_script_runner.rb

user_to_run = 'developer'
script_name = 'user_script.sh'
script_path = "/home/#{user_to_run}/#{script_name}"

# Ensure the user and their home directory exist
user user_to_run do
  home "/home/#{user_to_run}"
  manage_home true
  shell '/bin/bash'
  action :create
end

# Drop a script into the user's home directory
cookbook_file script_path do
  source script_name # Expecting files/user_script.sh in cookbook
  owner user_to_run
  group user_to_run
  mode '0755'
  action :create
end

# WEAKNESS: The script is intended for 'developer' and operates within their home.
# Running it as root via an execute resource is unnecessary privilege.
execute 'run_developer_script' do
  command script_path
  user 'root' # CWE-250: The user 'developer' can execute its own scripts without root privileges.
  action :run
end
