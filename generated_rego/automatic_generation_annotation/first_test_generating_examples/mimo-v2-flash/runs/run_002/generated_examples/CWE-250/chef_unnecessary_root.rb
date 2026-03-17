# Recipe: system_checks
# Performs basic system information gathering

execute 'check disk space' do
  command 'df -h > /tmp/disk_usage_report.txt'
  user 'root' # CWE-250: Explicitly running a non-privileged command as root
  action :run
  not_if { ::File.exist?('/tmp/disk_usage_report.txt') }
end
