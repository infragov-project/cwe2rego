# In Chef, configuration often happens via templates.
# This recipe would set up an Apache vhost with an older TLS protocol.
template '/etc/httpd/conf.d/my-weak-site.conf' do
  source 'vhost.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
  variables(
    {
      :server_name => 'weak.example.com',
      :document_root => '/var/www/weak_site',
      :ssl_enabled => true,
      # Explicitly set weak SSL protocol
      :ssl_protocol => 'TLSv1.0', # Inadequate TLS protocol
      :ssl_cipher_suite => 'HIGH:!aNULL:!MD5' # Still using default ciphers allowed by TLSv1.0
    }
  )
  notifies :reload, 'service[httpd]', :delayed
end

# Hypothetical content for templates/default/vhost.conf.erb:
# <VirtualHost *:443>
#   ServerName <%= @server_name %>
#   DocumentRoot <%= @document_root %>
#   SSLEngine On
#   SSLProtocol <%= @ssl_protocol %>
#   SSLCipherSuite <%= @ssl_cipher_suite %>
# </VirtualHost>

service 'httpd' do
  action [:enable, :start]
end
