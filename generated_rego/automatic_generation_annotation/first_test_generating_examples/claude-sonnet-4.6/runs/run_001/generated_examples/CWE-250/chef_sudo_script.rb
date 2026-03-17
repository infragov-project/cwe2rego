# Cookbook:: my_cookbook 
# Recipe:: privileged_script 

script 'execute a sudo command' do 
  interpreter 'bash' 
  code <<-EOH
    echo "Running an escalated command using sudo."
    sudo touch /var/log/sensitive_log.txt
  EOH
  action :run 
end