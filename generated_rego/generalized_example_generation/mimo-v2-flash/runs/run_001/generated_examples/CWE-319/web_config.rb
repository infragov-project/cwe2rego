template '/etc/webserver/settings.conf' do
  source 'settings.erb'
  variables(
    :protocol => 'http',
    :ssl_enabled => false,
    :force_https => false
  )
  action :create
end