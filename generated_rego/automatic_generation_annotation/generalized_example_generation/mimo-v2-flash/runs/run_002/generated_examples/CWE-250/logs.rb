execute 'clear-logs' do
  command 'rm /var/log/app/*'
  user 'root'
end
