file '/etc/sensitive_config.conf' do
  content 'secret_key=supersecure'
  mode '0777' # CWE-250: Overly permissive file permissions
  owner 'root'
  group 'root'
end
