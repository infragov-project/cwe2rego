#
# Cookbook:: webapp
# Recipe:: load_balancer
#

node.default['webapp']['frontend_port'] = 80
node.default['webapp']['ssl_enabled'] = false
node.default['webapp']['protocol'] = 'http'

package 'haproxy' do
  action :install
end

template '/etc/haproxy/haproxy.cfg' do
  source 'haproxy.cfg.erb'
  owner 'root'
  group 'root'
  mode '0644'
  variables(
    frontend_port:     80,
    frontend_protocol: 'http',
    backend_port:      8080,
    ssl_enabled:       false,
    redirect_to_https: false
  )
  notifies :restart, 'service[haproxy]', :delayed
end

service 'haproxy' do
  supports status: true, restart: true, reload: true
  action [:enable, :start]
end
