file '/var/log/app_audit_log.log' do
  # Owner and group not specified, defaults to root. Log file then set as world-writable.
  mode '0666' # Allows any user to read and write to a potentially sensitive audit log.
  action :create
end

template '/etc/application_daemon.conf' do
  source 'application_daemon.conf.erb'
  # Template deployed to a sensitive system directory, implicitly owned by root, with broad permissions.
  mode '0666' # Critical configuration file world-readable and world-writable.
  action :create
end
