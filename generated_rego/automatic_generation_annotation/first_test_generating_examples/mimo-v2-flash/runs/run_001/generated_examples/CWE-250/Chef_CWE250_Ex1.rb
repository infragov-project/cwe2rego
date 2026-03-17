directory '/tmp/sensitive_app_data' do
  owner 'root'
  group 'root'
  mode '0777' # Excessive permissions (world-writable, world-executable)
  action :create
end

execute 'create_privileged_and_exposed_file' do
  command 'echo "Highly confidential data" > /tmp/sensitive_app_data/confidential.txt && chmod 666 /tmp/sensitive_app_data/confidential.txt'
  # This execute block runs as root by default without explicit user context, creating a world-writable file.
  action :run
end
