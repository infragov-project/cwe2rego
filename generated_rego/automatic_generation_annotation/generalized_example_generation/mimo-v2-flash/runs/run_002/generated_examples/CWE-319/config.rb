file '/etc/webserver.conf' do
  content "protocol http
ssl_enforcement disabled"
  mode '0644'
end
