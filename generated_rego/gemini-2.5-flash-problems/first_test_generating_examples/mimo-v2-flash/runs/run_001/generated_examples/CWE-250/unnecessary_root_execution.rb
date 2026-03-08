# file: unnecessary_root_execution.rb
# This recipe executes a command that doesn't strictly require root,
# but the 'execute' resource runs as root by default, inheriting unnecessary privileges.

file '/opt/app/log_message.txt' do
  content "Application started at #{Time.now}
"
  owner 'app_user' # Assuming app_user exists and owns this part
  group 'app_group'
  mode '0644'
  action :create_if_missing
end

execute 'log_application_startup_info' do
  command "echo 'Application successfully initialized.' >> /opt/app/log_message.txt"
  # By default, this runs as 'root'. If /opt/app/log_message.txt is owned by app_user,
  # and 'app_user' has write permissions, this could potentially be run as 'app_user'
  # using the 'user' attribute. Running as root here is excessive.
  action :run
end