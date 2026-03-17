node.default['myapp']['security']['encryption_algorithm'] = 'DES'
node.default['myapp']['security']['key_size'] = 56

template '/etc/myapp/config.ini' do
  source 'config.ini.erb'
  variables(
    algorithm: node['myapp']['security']['encryption_algorithm'],
    key_size: node['myapp']['security']['key_size']
  )
end
