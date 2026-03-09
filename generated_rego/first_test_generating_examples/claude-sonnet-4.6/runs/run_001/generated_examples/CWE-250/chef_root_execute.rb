# Cookbook:: my_cookbook 
# Recipe:: default 

execute 'run a command as root' do 
  command 'echo "This command runs as root." > /root/test_file.txt' 
  user 'root' 
  action :run 
end