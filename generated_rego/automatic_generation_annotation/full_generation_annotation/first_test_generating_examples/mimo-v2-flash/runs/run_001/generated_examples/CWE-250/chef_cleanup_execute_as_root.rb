execute 'cleanup old logs' do
  command 'find /var/log/myapp -type f -name "*.log" -mtime +30 -delete'
  action :run
end
